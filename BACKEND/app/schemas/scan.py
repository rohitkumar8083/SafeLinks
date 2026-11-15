"""Scan request, response, and check models matching the shared contract."""

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field


class ScanMode(StrEnum):
    FULL = "full"
    QUICK = "quick"


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class CheckId(StrEnum):
    URL_STRUCTURE = "url_structure"
    ML_PHISHING = "ml_phishing"
    DOMAIN_AGE = "domain_age"
    SSL_CERTIFICATE = "ssl_certificate"
    REDIRECT_CHAIN = "redirect_chain"
    GOOGLE_SAFE_BROWSING = "google_safe_browsing"
    VIRUSTOTAL = "virustotal"
    URLHAUS = "urlhaus"


class CheckCategory(StrEnum):
    PHISHING = "phishing"
    MALWARE = "malware"
    REPUTATION = "reputation"
    DOMAIN = "domain"
    SSL = "ssl"
    URL_STRUCTURE = "url_structure"


class CheckStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    SKIPPED = "skipped"
    ERROR = "error"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(StrEnum):
    LIKELY_SAFE = "likely_safe"
    SUSPICIOUS = "suspicious"
    LIKELY_MALICIOUS = "likely_malicious"
    UNKNOWN = "unknown"


class ScanErrorCode(StrEnum):
    SCAN_FAILED = "SCAN_FAILED"
    TIMEOUT = "TIMEOUT"


# -------------------------------------------------------------------------
# Request & Response Models
# -------------------------------------------------------------------------


class CreateScanRequest(BaseModel):
    url: str = Field(..., max_length=2048, description="Target URL to scan, max 2048 chars")
    mode: ScanMode = Field(default=ScanMode.FULL, description="Scan execution mode: full or quick")


class CreateScanResponse(BaseModel):
    scan_id: str
    status: Literal["queued"] = "queued"
    submitted_url: str
    normalized_url: str


class Check(BaseModel):
    id: CheckId
    name: str
    category: CheckCategory
    status: CheckStatus
    severity: Severity
    title: str
    detail: str
    evidence: list[str]
    source: str


class MlFeature(BaseModel):
    name: str
    value: str | int | float | bool
    impact: float = Field(..., ge=-1.0, le=1.0)


class MlResult(BaseModel):
    phishing_probability: float = Field(..., ge=0.0, le=1.0)
    model_version: str
    top_features: list[MlFeature]


class SslInfo(BaseModel):
    valid: bool
    issuer: str
    expires_at: str
    days_remaining: int


class DomainInfo(BaseModel):
    domain: str
    age_days: int | None = None
    registrar: str | None = None
    ssl: SslInfo | None = None


class ScanResult(BaseModel):
    risk_score: int = Field(..., ge=0, le=100)
    verdict: Verdict
    confidence: float = Field(..., ge=0.0, le=1.0)
    summary: str
    recommendations: list[str]
    ml: MlResult | None = None
    domain_info: DomainInfo | None = None


class Progress(BaseModel):
    completed_checks: int
    total_checks: int = 8


class ScanError(BaseModel):
    code: ScanErrorCode
    message: str


class ScanResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    submitted_url: str
    normalized_url: str
    created_at: str
    completed_at: str | None = None
    progress: Progress
    checks: list[Check]
    result: ScanResult | None = None
    error: ScanError | None = None


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    version: str
    ml_model_loaded: bool
