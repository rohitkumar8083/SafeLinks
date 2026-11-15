"""Scan persistence abstractions and in-memory implementation."""

import asyncio
import logging
from abc import ABC, abstractmethod
from copy import deepcopy
from datetime import UTC, datetime

from app.schemas.scan import (
    Check,
    CheckStatus,
    ScanError,
    ScanResponse,
    ScanResult,
    ScanStatus,
)

logger = logging.getLogger("safelinks.repo")


class ScanRepository(ABC):
    """Abstract interface for storing and retrieving scans."""

    @abstractmethod
    async def create(self, scan: ScanResponse) -> None:
        """Stores a new scan record."""
        pass

    @abstractmethod
    async def get(self, scan_id: str) -> ScanResponse | None:
        """Retrieves a deep-copied snapshot of the scan, or None if missing."""
        pass

    @abstractmethod
    async def update_check(self, scan_id: str, check: Check) -> None:
        """Updates a specific check outcome and increments progress accordingly."""
        pass

    @abstractmethod
    async def set_status(
        self,
        scan_id: str,
        status: ScanStatus,
        error: ScanError | None = None,
        completed_at: str | None = None,
    ) -> None:
        """Updates the status and optional error/completion timestamp of a scan."""
        pass

    @abstractmethod
    async def set_result(self, scan_id: str, result: ScanResult, completed_at: str) -> None:
        """Attaches final computed scan result and marks scan complete."""
        pass

    @abstractmethod
    async def delete_expired(self, ttl_minutes: int) -> int:
        """Purges scans older than the specified TTL in minutes."""
        pass

    @abstractmethod
    async def count(self) -> int:
        """Returns the current number of stored scans."""
        pass


class InMemoryScanRepository(ScanRepository):
    """Thread-safe in-memory scan repository guarded by an asyncio.Lock."""

    def __init__(self, max_stored_scans: int = 5000, ttl_minutes: int = 60) -> None:
        self._lock = asyncio.Lock()
        self._scans: dict[str, ScanResponse] = {}
        self._max_stored_scans = max_stored_scans
        self._ttl_minutes = ttl_minutes
        self._purge_task: asyncio.Task | None = None

    async def create(self, scan: ScanResponse) -> None:
        async with self._lock:
            # Enforce max stored scans cap by evicting oldest
            if len(self._scans) >= self._max_stored_scans:
                oldest_id = next(iter(self._scans))
                del self._scans[oldest_id]
                logger.info("Evicted oldest scan %s to satisfy MAX_STORED_SCANS limit", oldest_id)

            self._scans[scan.scan_id] = deepcopy(scan)

    async def get(self, scan_id: str) -> ScanResponse | None:
        async with self._lock:
            scan = self._scans.get(scan_id)
            if scan is None:
                return None
            return deepcopy(scan)

    async def update_check(self, scan_id: str, check: Check) -> None:
        async with self._lock:
            scan = self._scans.get(scan_id)
            if scan is None:
                return

            # Replace check matching id
            updated = False
            for idx, c in enumerate(scan.checks):
                if c.id == check.id:
                    scan.checks[idx] = deepcopy(check)
                    updated = True
                    break

            if not updated:
                scan.checks.append(deepcopy(check))

            # Recalculate completed checks count
            completed = sum(
                1 for c in scan.checks if c.status in (CheckStatus.DONE, CheckStatus.SKIPPED, CheckStatus.ERROR)
            )
            scan.progress.completed_checks = completed

    async def set_status(
        self,
        scan_id: str,
        status: ScanStatus,
        error: ScanError | None = None,
        completed_at: str | None = None,
    ) -> None:
        async with self._lock:
            scan = self._scans.get(scan_id)
            if scan is None:
                return
            scan.status = status
            if error is not None:
                scan.error = deepcopy(error)
            if completed_at is not None:
                scan.completed_at = completed_at

    async def set_result(self, scan_id: str, result: ScanResult, completed_at: str) -> None:
        async with self._lock:
            scan = self._scans.get(scan_id)
            if scan is None:
                return
            scan.result = deepcopy(result)
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = completed_at

    async def delete_expired(self, ttl_minutes: int) -> int:
        now = datetime.now(UTC)
        expired_ids: list[str] = []

        async with self._lock:
            for s_id, scan in self._scans.items():
                try:
                    # Parse ISO UTC timestamp ending in 'Z'
                    ts_str = scan.created_at.rstrip("Z")
                    created_dt = datetime.fromisoformat(ts_str).replace(tzinfo=UTC)
                    age_seconds = (now - created_dt).total_seconds()
                    if age_seconds > (ttl_minutes * 60):
                        expired_ids.append(s_id)
                except Exception as e:
                    logger.warning("Could not parse created_at timestamp for scan %s: %s", s_id, e)

            for s_id in expired_ids:
                del self._scans[s_id]

        if expired_ids:
            logger.info("Purged %d expired scans from in-memory repository", len(expired_ids))
        return len(expired_ids)

    async def count(self) -> int:
        async with self._lock:
            return len(self._scans)

    def start_purge_worker(self) -> None:
        """Starts background periodic cleanup task."""
        if self._purge_task is None or self._purge_task.done():
            self._purge_task = asyncio.create_task(self._purge_loop())

    def stop_purge_worker(self) -> None:
        """Cancels background periodic cleanup task."""
        if self._purge_task and not self._purge_task.done():
            self._purge_task.cancel()
            self._purge_task = None

    async def _purge_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(60)
                await self.delete_expired(self._ttl_minutes)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error in repository purge loop: %s", e)
