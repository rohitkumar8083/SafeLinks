"""FastAPI dependency providers."""

from fastapi import Depends

from app.config import Settings, settings
from app.repositories.scan_repo import InMemoryScanRepository, ScanRepository
from app.services.scan_orchestrator import ScanOrchestrator

# Repository singleton instance
_scan_repo_instance: ScanRepository | None = None
_scan_orchestrator_instance: ScanOrchestrator | None = None


def get_settings() -> Settings:
    return settings


def get_repository() -> ScanRepository:
    """Returns the application-level scan repository singleton."""
    global _scan_repo_instance
    if _scan_repo_instance is None:
        _scan_repo_instance = InMemoryScanRepository(
            max_stored_scans=settings.MAX_STORED_SCANS,
            ttl_minutes=settings.SCAN_TTL_MINUTES,
        )
    return _scan_repo_instance


def set_repository(repo: ScanRepository | None) -> None:
    """Override or clear repository instance (useful for testing)."""
    global _scan_repo_instance
    _scan_repo_instance = repo


def get_orchestrator(
    repo: ScanRepository = Depends(get_repository),
    app_settings: Settings = Depends(get_settings),
) -> ScanOrchestrator:
    """Returns the scan orchestrator service instance."""
    global _scan_orchestrator_instance
    if _scan_orchestrator_instance is None or _scan_orchestrator_instance.repo != repo:
        _scan_orchestrator_instance = ScanOrchestrator(repo=repo, settings=app_settings)
    return _scan_orchestrator_instance
