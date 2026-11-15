"""Base class and outcome data structure for security checks."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Literal

from app.schemas.scan import (
    Check,
    CheckCategory,
    CheckId,
    CheckStatus,
    Severity,
)
from app.services.context import ScanContext


@dataclass
class CheckOutcome:
    """Standardized outcome returned by a check execution."""

    status: CheckStatus
    severity: Severity = Severity.INFO
    title: str = ""
    detail: str = ""
    evidence: list[str] = field(default_factory=list)
    points: int | None = None
    signal: Literal["none", "soft", "hard"] = "none"
    floor: int | None = None
    data: dict[str, Any] = field(default_factory=dict)

    def to_check_model(self, check_id: CheckId, name: str, category: CheckCategory, source: str) -> Check:
        return Check(
            id=check_id,
            name=name,
            category=category,
            status=self.status,
            severity=self.severity,
            title=self.title,
            detail=self.detail,
            evidence=self.evidence,
            source=source,
        )


class BaseCheck(ABC):
    """Abstract base check contract."""

    id: CheckId
    name: str
    category: CheckCategory
    source: str
    runs_in_quick_mode: bool = False

    @abstractmethod
    async def run(self, ctx: ScanContext) -> CheckOutcome:
        """Executes the check logic and returns a CheckOutcome."""
        pass
