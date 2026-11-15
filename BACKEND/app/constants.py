"""Shared application constants for SafeLinks API."""

from typing import Final

# Total checks contract count
TOTAL_CHECKS_COUNT: Final[int] = 8

# All check IDs in the exact contract order
ORDERED_CHECK_IDS: Final[tuple[str, ...]] = (
    "url_structure",
    "ml_phishing",
    "domain_age",
    "ssl_certificate",
    "redirect_chain",
    "google_safe_browsing",
    "virustotal",
    "urlhaus",
)

# Checks that execute in 'quick' mode
QUICK_MODE_CHECK_IDS: Final[set[str]] = {
    "url_structure",
    "ml_phishing",
}

# Verdict score thresholds
VERDICT_SAFE_MAX: Final[int] = 29
VERDICT_SUSPICIOUS_MAX: Final[int] = 69
# 70-100 is likely_malicious

# Minimum required completed checks to compute verdict
MIN_COMPLETED_CHECKS_FULL: Final[int] = 3
MIN_COMPLETED_CHECKS_QUICK: Final[int] = 2

# HTTP constants
HEADER_REQUEST_ID: Final[str] = "X-Request-ID"
HEADER_CACHE_CONTROL: Final[str] = "Cache-Control"
HEADER_CACHE_CONTROL_VALUE: Final[str] = "no-store"
DEFAULT_USER_AGENT: Final[str] = "SafeLinksBot/1.0 (security scanner)"

MAX_URL_LENGTH: Final[int] = 2048
MAX_BODY_BYTES: Final[int] = 65536  # 64 KB limit
DEFAULT_PORTS: Final[dict[str, int]] = {"http": 80, "https": 443}
