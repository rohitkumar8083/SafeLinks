"""Google Safe Browsing reputation check with swappable API client abstraction."""

import logging

import httpx

from app.core.cache import get_threat_intel_cache
from app.schemas.scan import CheckCategory, CheckId, CheckStatus, Severity
from app.services.checks.base import BaseCheck, CheckOutcome
from app.services.context import ScanContext

logger = logging.getLogger("safelinks.checks.safebrowsing")

THREAT_DESCRIPTIONS: dict[str, str] = {
    "SOCIAL_ENGINEERING": "phishing / deceptive site",
    "MALWARE": "malware distributor or host",
    "UNWANTED_SOFTWARE": "unwanted or deceptive software",
    "POTENTIALLY_HARMFUL_APPLICATION": "potentially harmful mobile application",
    "THREAT_TYPE_UNSPECIFIED": "unspecified security threat",
}


class SafeBrowsingClient:
    """Client for Google Safe Browsing v4 threatMatches lookup API."""

    def __init__(self, api_key: str, client_version: str = "1.0.0") -> None:
        self.api_key = api_key
        self.client_version = client_version
        self.endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

    async def lookup(self, url: str, http_client: httpx.AsyncClient) -> tuple[bool, list[str]]:
        """Queries Google Safe Browsing v4 lookup endpoint.

        Returns (is_flagged, threat_types_list).
        Raises httpx.HTTPStatusError or httpx.RequestError on failure.
        """
        payload = {
            "client": {
                "clientId": "safelinks",
                "clientVersion": self.client_version,
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        # Query with api_key passed as query parameter
        response = await http_client.post(
            self.endpoint,
            params={"key": self.api_key},
            json=payload,
            timeout=8.0,
        )
        response.raise_for_status()

        data = response.json()
        matches = data.get("matches", [])
        if not matches:
            return False, []

        threat_types: list[str] = [m.get("threatType", "THREAT_TYPE_UNSPECIFIED") for m in matches]
        return True, threat_types


class GoogleSafeBrowsingCheck(BaseCheck):
    """Reputation evaluation against Google Safe Browsing v4 API."""

    id = CheckId.GOOGLE_SAFE_BROWSING
    name = "Google Safe Browsing"
    category = CheckCategory.REPUTATION
    source = "Google Safe Browsing"
    runs_in_quick_mode = False

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        # Check API key configuration
        api_key = ctx.settings.GOOGLE_SAFE_BROWSING_API_KEY
        if not api_key:
            return CheckOutcome(
                status=CheckStatus.SKIPPED,
                severity=Severity.INFO,
                title="Not configured",
                detail="This check needs an API key on the server.",
                evidence=["Google Safe Browsing API key was not configured on this instance."],
                signal="none",
            )

        cache = get_threat_intel_cache(ttl_seconds=ctx.settings.CACHE_TTL_SECONDS)
        cached = await cache.get(self.id.value, ctx.normalized_url)
        if cached:
            return cached

        client = SafeBrowsingClient(api_key=api_key, client_version=ctx.settings.APP_VERSION)

        try:
            is_matched, threat_types = await client.lookup(ctx.normalized_url, ctx.http_client)
        except httpx.HTTPStatusError as e:
            logger.warning("Safe Browsing API returned HTTP error: %d", e.response.status_code)
            return CheckOutcome(
                status=CheckStatus.ERROR,
                severity=Severity.INFO,
                title="Google Safe Browsing error",
                detail="Google Safe Browsing service returned an unexpected error.",
                evidence=[],
                signal="none",
            )
        except Exception as e:
            logger.warning("Safe Browsing lookup failed: %s", e)
            return CheckOutcome(
                status=CheckStatus.ERROR,
                severity=Severity.INFO,
                title="Google Safe Browsing error",
                detail="Google Safe Browsing service is currently unavailable.",
                evidence=[],
                signal="none",
            )

        if is_matched:
            evidence: list[str] = []
            for t in threat_types:
                desc = THREAT_DESCRIPTIONS.get(t, t.lower().replace("_", " "))
                evidence.append(f"Threat detected: {t} ({desc})")

            outcome = CheckOutcome(
                status=CheckStatus.DONE,
                severity=Severity.CRITICAL,
                title="Google Safe Browsing match",
                detail="This URL is blacklisted in Google Safe Browsing as a known malicious or deceptive site.",
                evidence=evidence,
                points=95,
                signal="hard",
                floor=92,
                data={"threat_types": threat_types},
            )
        else:
            outcome = CheckOutcome(
                status=CheckStatus.DONE,
                severity=Severity.INFO,
                title="Clean in Google Safe Browsing",
                detail="No threat matches found in Google Safe Browsing database.",
                evidence=["URL was not found on Google Safe Browsing threat lists."],
                points=0,
                signal="none",
                data={"matches": []},
            )

        await cache.set(self.id.value, ctx.normalized_url, outcome)
        return outcome
