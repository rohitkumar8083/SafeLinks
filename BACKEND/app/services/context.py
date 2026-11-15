"""Context object passed to every check execution."""

from dataclasses import dataclass, field
from typing import Any

import httpx

from app.config import Settings
from app.schemas.scan import ScanMode
from app.services.url_normalizer import NormalizedURL


@dataclass
class ScanContext:
    """Execution context provided to all security checks."""

    scan_id: str
    mode: ScanMode
    submitted_url: str
    normalized_url: str
    parsed: NormalizedURL
    settings: Settings
    http_client: httpx.AsyncClient
    cache: Any = None
    rate_limiter: Any = None
    ml_predictor: Any = None
    extra: dict[str, Any] = field(default_factory=dict)
