"""Scan orchestrator managing asynchronous execution, check concurrency, and progress."""

import asyncio
import logging
import uuid
from datetime import UTC, datetime

from app.constants import QUICK_MODE_CHECK_IDS
from app.core.errors import RateLimitedError
from app.core.http_client import get_shared_client
from app.core.ssrf_guard import validate_target_or_raise
from app.ml.predict import get_shared_predictor
from app.repositories.scan_repo import ScanRepository
from app.schemas.scan import (
    Check,
    CheckId,
    CheckStatus,
    CreateScanRequest,
    CreateScanResponse,
    Progress,
    ScanError,
    ScanErrorCode,
    ScanMode,
    ScanResponse,
    ScanStatus,
    Severity,
)
from app.services.checks.base import BaseCheck, CheckOutcome
from app.services.checks.registry import CHECK_REGISTRY, build_initial_checks
from app.services.context import ScanContext
from app.services.gemini_analyst import generate_ai_analysis
from app.services.risk_scoring import compute_scan_result
from app.services.url_normalizer import parse_and_normalize_url

logger = logging.getLogger("safelinks.orchestrator")

# Strong reference set for background scan tasks
_active_tasks: set[asyncio.Task] = set()
_active_scans_count: int = 0
_concurrency_lock = asyncio.Lock()


def get_active_tasks() -> set[asyncio.Task]:
    return _active_tasks


async def cancel_all_tasks() -> None:
    """Cancels all currently running scan background tasks during shutdown."""
    for task in list(_active_tasks):
        if not task.done():
            task.cancel()
    if _active_tasks:
        await asyncio.gather(*_active_tasks, return_exceptions=True)
    _active_tasks.clear()


class ScanOrchestrator:
    """Orchestrates URL scanning, concurrency control, and progress reporting."""

    def __init__(self, repo: ScanRepository, settings: any) -> None:
        self.repo = repo
        self.settings = settings

    async def initiate_scan(self, req: CreateScanRequest) -> CreateScanResponse:
        """Validates input, runs SSRF pre-check, enqueues the scan, and returns 202."""
        global _active_scans_count

        # 1. Enforce max concurrent scans limit
        async with _concurrency_lock:
            if _active_scans_count >= self.settings.MAX_CONCURRENT_SCANS:
                logger.warning("Rejecting scan: active scans (%d) reached MAX_CONCURRENT_SCANS", _active_scans_count)
                raise RateLimitedError("The server is busy, please try again shortly")
            _active_scans_count += 1

        try:
            # 2. Validate and normalize URL
            parsed = parse_and_normalize_url(req.url)

            # 3. SSRF pre-check on target host and port
            await validate_target_or_raise(parsed.ascii_host, parsed.port)

            # 4. Generate scan ID and initialize check list
            scan_id = str(uuid.uuid4())
            now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

            initial_checks = build_initial_checks()
            completed_count = 0

            # In quick mode, initialize non-quick checks as skipped
            if req.mode == ScanMode.QUICK:
                for idx, c in enumerate(initial_checks):
                    if c.id.value not in QUICK_MODE_CHECK_IDS:
                        initial_checks[idx] = Check(
                            id=c.id,
                            name=c.name,
                            category=c.category,
                            status=CheckStatus.SKIPPED,
                            severity=Severity.INFO,
                            title="Skipped",
                            detail="Not run in quick mode",
                            evidence=[],
                            source=c.source,
                        )
                        completed_count += 1

            scan_record = ScanResponse(
                scan_id=scan_id,
                status=ScanStatus.QUEUED,
                submitted_url=req.url,
                normalized_url=parsed.normalized_url,
                created_at=now_iso,
                completed_at=None,
                progress=Progress(completed_checks=completed_count, total_checks=8),
                checks=initial_checks,
                result=None,
                error=None,
            )

            await self.repo.create(scan_record)

            # 5. Spawn background execution task with strong reference
            task = asyncio.create_task(self._run_scan(scan_id, req.mode, parsed))
            _active_tasks.add(task)

            def _on_done(t: asyncio.Task) -> None:
                global _active_scans_count
                _active_tasks.discard(t)
                asyncio.create_task(self._decrement_active_count())

            task.add_done_callback(_on_done)

            logger.info("Enqueued scan %s for host %s mode=%s", scan_id, parsed.ascii_host, req.mode.value)
            return CreateScanResponse(
                scan_id=scan_id,
                status="queued",
                submitted_url=req.url,
                normalized_url=parsed.normalized_url,
            )

        except Exception:
            # Decrement active count on synchronous failure before task launch
            async with _concurrency_lock:
                _active_scans_count = max(0, _active_scans_count - 1)
            raise

    async def _decrement_active_count(self) -> None:
        global _active_scans_count
        async with _concurrency_lock:
            _active_scans_count = max(0, _active_scans_count - 1)

    async def _run_scan(self, scan_id: str, mode: ScanMode, parsed: any) -> None:
        """Background worker executing the checks and updating scan progress."""
        try:
            # Mark running
            await self.repo.set_status(scan_id, ScanStatus.RUNNING)

            ctx = ScanContext(
                scan_id=scan_id,
                mode=mode,
                submitted_url=parsed.submitted_url,
                normalized_url=parsed.normalized_url,
                parsed=parsed,
                settings=self.settings,
                http_client=get_shared_client(),
                ml_predictor=get_shared_predictor(),
            )

            outcomes: dict[CheckId, CheckOutcome] = {}

            # Execute overall scan with overall timeout
            try:
                await asyncio.wait_for(
                    self._execute_all_checks(scan_id, mode, ctx, outcomes),
                    timeout=self.settings.OVERALL_SCAN_TIMEOUT_SECONDS,
                )
            except TimeoutError:
                logger.warning("Scan %s timed out overall (%ds)", scan_id, self.settings.OVERALL_SCAN_TIMEOUT_SECONDS)
                # Mark unfinished checks as error 'Timed out'
                current_scan = await self.repo.get(scan_id)
                if current_scan:
                    for c in current_scan.checks:
                        if c.status in (CheckStatus.PENDING, CheckStatus.RUNNING):
                            timed_out_check = Check(
                                id=c.id,
                                name=c.name,
                                category=c.category,
                                status=CheckStatus.ERROR,
                                severity=Severity.INFO,
                                title="Timed out",
                                detail="Check execution timed out.",
                                evidence=[],
                                source=c.source,
                            )
                            await self.repo.update_check(scan_id, timed_out_check)

                # Check if fewer than required checks succeeded
                current_scan = await self.repo.get(scan_id)
                done_count = sum(1 for c in current_scan.checks if c.status == CheckStatus.DONE) if current_scan else 0
                min_required = 2 if mode == ScanMode.QUICK else 3

                if done_count < min_required:
                    now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
                    await self.repo.set_status(
                        scan_id,
                        ScanStatus.FAILED,
                        error=ScanError(code=ScanErrorCode.TIMEOUT, message="Scan timed out before sufficient checks completed"),
                        completed_at=now_iso,
                    )
                    return

            # Compute scan result
            current_scan = await self.repo.get(scan_id)
            if not current_scan:
                return

            completed_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            scan_result = compute_scan_result(
                mode=mode,
                checks=current_scan.checks,
                outcomes=outcomes,
                target_domain=parsed.registered_domain,
            )

            # Optional: Enhance summary and recommendations using Gemini AI if configured
            if getattr(self.settings, "GEMINI_API_KEY", None):
                done_details = [
                    f"{c.name}: {c.detail}"
                    for c in current_scan.checks
                    if c.status == CheckStatus.DONE and c.detail
                ]
                ai_data = await generate_ai_analysis(
                    url=parsed.normalized_url,
                    risk_score=scan_result.risk_score,
                    verdict=scan_result.verdict.value,
                    findings=done_details,
                    http_client=ctx.http_client,
                    api_key=self.settings.GEMINI_API_KEY,
                    model=getattr(self.settings, "GEMINI_MODEL", "gemini-3-flash-preview"),
                )
                if ai_data:
                    scan_result.summary = ai_data["summary"]
                    scan_result.recommendations = ai_data["recommendations"]

            await self.repo.set_result(scan_id, scan_result, completed_at)
            logger.info("Completed scan %s with verdict %s", scan_id, scan_result.verdict.value)

        except asyncio.CancelledError:
            logger.info("Scan task %s was cancelled", scan_id)
            raise
        except Exception as e:
            logger.exception("Unexpected error in scan orchestrator for %s: %s", scan_id, e)
            now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            await self.repo.set_status(
                scan_id,
                ScanStatus.FAILED,
                error=ScanError(code=ScanErrorCode.SCAN_FAILED, message="An internal error occurred during scan execution"),
                completed_at=now_iso,
            )

    async def _execute_all_checks(
        self,
        scan_id: str,
        mode: ScanMode,
        ctx: ScanContext,
        outcomes: dict[CheckId, CheckOutcome],
    ) -> None:
        """Runs checks concurrently, updating progress immediately on completion."""
        tasks: list[asyncio.Task] = []

        for check in CHECK_REGISTRY:
            if mode == ScanMode.QUICK and check.id.value not in QUICK_MODE_CHECK_IDS:
                # Skipped in quick mode
                outcome = CheckOutcome(
                    status=CheckStatus.SKIPPED,
                    severity=Severity.INFO,
                    title="Skipped",
                    detail="Not run in quick mode",
                    evidence=[],
                    signal="none",
                )
                outcomes[check.id] = outcome
                continue

            tasks.append(asyncio.create_task(self._run_single_check(scan_id, check, ctx, outcomes)))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _run_single_check(
        self,
        scan_id: str,
        check: BaseCheck,
        ctx: ScanContext,
        outcomes: dict[CheckId, CheckOutcome],
    ) -> None:
        """Executes one individual check, catches errors, and immediately updates repository."""
        # 1. Update status to RUNNING
        running_check = Check(
            id=check.id,
            name=check.name,
            category=check.category,
            status=CheckStatus.RUNNING,
            severity=Severity.INFO,
            title="",
            detail="",
            evidence=[],
            source=check.source,
        )
        await self.repo.update_check(scan_id, running_check)

        # 2. Execute check wrapped in CHECK_TIMEOUT_SECONDS
        outcome: CheckOutcome
        try:
            outcome = await asyncio.wait_for(check.run(ctx), timeout=self.settings.CHECK_TIMEOUT_SECONDS)
        except TimeoutError:
            logger.warning("Check %s on scan %s timed out", check.id.value, scan_id)
            outcome = CheckOutcome(
                status=CheckStatus.ERROR,
                severity=Severity.INFO,
                title="Timed out",
                detail="This check timed out while executing.",
                evidence=["Execution exceeded check timeout limit."],
                signal="none",
            )
        except Exception as e:
            logger.exception("Check %s on scan %s failed with exception: %s", check.id.value, scan_id, e)
            outcome = CheckOutcome(
                status=CheckStatus.ERROR,
                severity=Severity.INFO,
                title="Check error",
                detail="An internal error occurred while executing this check.",
                evidence=[],
                signal="none",
            )

        outcomes[check.id] = outcome

        # 3. Update check model immediately in repository
        finished_check = outcome.to_check_model(check.id, check.name, check.category, check.source)
        await self.repo.update_check(scan_id, finished_check)
