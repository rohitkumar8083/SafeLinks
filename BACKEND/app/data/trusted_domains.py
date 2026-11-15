"""Authoritative trusted domains allowlist with dampening logic."""

import logging
from pathlib import Path

logger = logging.getLogger("safelinks.trusted")

# Curated allowlist of top global authoritative registered domains
BASE_TRUSTED_DOMAINS: frozenset[str] = frozenset({
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "github.com",
    "wikipedia.org",
    "cloudflare.com",
    "mozilla.org",
    "python.org",
    "stackoverflow.com",
    "linkedin.com",
    "netflix.com",
    "spotify.com",
    "nytimes.com",
    "bbc.com",
    "cnn.com",
    "zoom.us",
    "slack.com",
    "dropbox.com",
    "adobe.com",
    "pypi.org",
    "apache.org",
    "w3.org",
    "ietf.org",
})

_loaded_trusted_domains: set[str] = set(BASE_TRUSTED_DOMAINS)


def load_tranco_top_domains(file_path: Path | None = None) -> None:
    """Optionally loads top domains from a Tranco CSV export."""
    path = file_path or Path("app/ml/data/raw/benign_domains.csv")
    if path.exists():
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                for idx, line in enumerate(f):
                    if idx >= 5000:  # Load top 5,000 domains
                        break
                    parts = line.strip().split(",")
                    domain = parts[1].strip().lower() if len(parts) > 1 else parts[0].strip().lower()
                    if domain and "." in domain and domain not in ("domain", "rank"):
                        _loaded_trusted_domains.add(domain)
            logger.info("Loaded trusted domains from %s (total: %d)", path, len(_loaded_trusted_domains))
        except Exception as e:
            logger.warning("Failed to load Tranco trusted domains from %s: %s", path, e)


def is_trusted_domain(registered_domain: str) -> bool:
    """Checks whether the exact registered domain is present in the trusted allowlist."""
    if not registered_domain:
        return False
    return registered_domain.lower() in _loaded_trusted_domains
