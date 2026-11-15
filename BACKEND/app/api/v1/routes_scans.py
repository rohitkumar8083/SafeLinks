"""URL scan submission and progress polling endpoints."""

import logging

from fastapi import APIRouter, Depends, Request, status

from app.api.deps import get_orchestrator, get_repository
from app.config import settings
from app.core.errors import NotFoundError
from app.core.rate_limit import limiter
from app.repositories.scan_repo import ScanRepository
from app.schemas.errors import ErrorResponse
from app.schemas.scan import (
    CreateScanRequest,
    CreateScanResponse,
    ScanResponse,
)
from app.services.scan_orchestrator import ScanOrchestrator

logger = logging.getLogger("safelinks.api.scans")

router = APIRouter(tags=["scans"])


def _scan_rate_limit() -> str:
    return f"{settings.RATE_LIMIT_SCANS_PER_MINUTE}/minute"


def _read_rate_limit() -> str:
    return f"{settings.RATE_LIMIT_READS_PER_MINUTE}/minute"


@router.post(
    "/scans",
    response_model=CreateScanResponse,
    status_code=status.HTTP_202_ACCEPTED,
    operation_id="create_scan",
    summary="Submit URL for security scanning",
    description="Validates and normalizes target URL, applies SSRF pre-check, and initiates asynchronous multi-vector security analysis.",
    responses={
        202: {"model": CreateScanResponse, "description": "Scan successfully queued"},
        422: {"model": ErrorResponse, "description": "Invalid URL, unsupported scheme, or blocked SSRF target"},
        429: {"model": ErrorResponse, "description": "Server busy or rate limit exceeded"},
        500: {"model": ErrorResponse, "description": "Internal server error"},
    },
)
@limiter.limit(_scan_rate_limit)
async def create_scan(
    request: Request,
    payload: CreateScanRequest,
    orchestrator: ScanOrchestrator = Depends(get_orchestrator),
) -> CreateScanResponse:
    """Creates and starts an asynchronous security scan."""
    return await orchestrator.initiate_scan(payload)


@router.get(
    "/scans/{scan_id}",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    operation_id="get_scan",
    summary="Poll scan status and results",
    description="Retrieves a snapshot of the scan lifecycle status, per-check progress, and final risk score upon completion.",
    responses={
        200: {"model": ScanResponse, "description": "Current scan progress snapshot or completed analysis report"},
        404: {"model": ErrorResponse, "description": "Scan ID not found or has expired"},
        429: {"model": ErrorResponse, "description": "Poll rate limit exceeded"},
        500: {"model": ErrorResponse, "description": "Internal server error"},
    },
)
@limiter.limit(_read_rate_limit)
async def get_scan(
    request: Request,
    scan_id: str,
    repo: ScanRepository = Depends(get_repository),
) -> ScanResponse:
    """Retrieves current scan progress or final report."""
    scan = await repo.get(scan_id)
    if scan is None:
        raise NotFoundError(f"Scan with ID '{scan_id}' was not found or has expired")
    return scan
