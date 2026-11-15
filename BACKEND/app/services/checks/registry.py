"""Check registry defining all 8 security checks in contract order."""

from app.schemas.scan import Check, CheckStatus, Severity
from app.services.checks.base import BaseCheck
from app.services.checks.domain_age import DomainAgeCheck
from app.services.checks.google_safe_browsing import GoogleSafeBrowsingCheck
from app.services.checks.ml_phishing import MlPhishingCheck
from app.services.checks.redirect_chain import RedirectChainCheck
from app.services.checks.ssl_certificate import SslCertificateCheck
from app.services.checks.url_structure import UrlStructureCheck
from app.services.checks.urlhaus import UrlhausCheck
from app.services.checks.virustotal import VirusTotalCheck

# The 8 checks in the exact order required by the API contract
CHECK_REGISTRY: list[BaseCheck] = [
    UrlStructureCheck(),
    MlPhishingCheck(),
    DomainAgeCheck(),
    SslCertificateCheck(),
    RedirectChainCheck(),
    GoogleSafeBrowsingCheck(),
    VirusTotalCheck(),
    UrlhausCheck(),
]


def get_all_checks() -> list[BaseCheck]:
    """Returns the ordered registry of security checks."""
    return list(CHECK_REGISTRY)


def build_initial_checks() -> list[Check]:
    """Constructs the initial 8 checks with pending status per contract Rule 1."""
    return [
        Check(
            id=chk.id,
            name=chk.name,
            category=chk.category,
            status=CheckStatus.PENDING,
            severity=Severity.INFO,
            title="",
            detail="",
            evidence=[],
            source=chk.source,
        )
        for chk in CHECK_REGISTRY
    ]
