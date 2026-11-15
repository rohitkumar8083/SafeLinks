"""URLhaus threat intelligence check detecting malware distribution sites."""

import logging

from app.core.cache import get_threat_intel_cache
from app.schemas.scan import CheckCategory, CheckId, CheckStatus, Severity
from app.services.checks.base import BaseCheck, CheckOutcome
from app.services.context import ScanContext

logger = logging.getLogger("safelinks.checks.urlhaus")


class UrlhausCheck(BaseCheck):
    """Malware and botnet distribution check via abuse.ch URLhaus API."""

    id = CheckId.URLHAUS
    name = "URLhaus"
    category = CheckCategory.MALWARE
    source = "abuse.ch URLhaus"
    runs_in_quick_mode = False

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        auth_key = ctx.settings.URLHAUS_AUTH_KEY
        if not auth_key:
            return CheckOutcome(
                status=CheckStatus.SKIPPED,
                severity=Severity.INFO,
                title="Not configured",
                detail="This check needs an API key on the server.",
                evidence=["URLhaus Auth-Key was not configured on this instance."],
                signal="none",
            )

        cache = get_threat_intel_cache(ttl_seconds=ctx.settings.CACHE_TTL_SECONDS)
        cached = await cache.get(self.id.value, ctx.normalized_url)
        if cached:
            return cached

        endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
        headers = {
            "Auth-Key": auth_key,
            "Accept": "application/json",
        }
        form_data = {"url": ctx.normalized_url}

        try:
            resp = await ctx.http_client.post(endpoint, headers=headers, data=form_data, timeout=8.0)
            if resp.status_code != 200:
                return CheckOutcome(
                    status=CheckStatus.ERROR,
                    severity=Severity.INFO,
                    title="URLhaus error",
                    detail=f"URLhaus service returned HTTP error ({resp.status_code}).",
                    signal="none",
                )

            data = resp.json()
        except Exception as e:
            logger.warning("URLhaus request failed: %s", e)
            return CheckOutcome(
                status=CheckStatus.ERROR,
                severity=Severity.INFO,
                title="URLhaus error",
                detail="URLhaus service communication failed.",
                signal="none",
            )

        query_status = data.get("query_status")

        # 1. Listed in URLhaus
        if query_status == "ok":
            url_status = str(data.get("url_status", "")).lower()
            threat = data.get("threat", "malware download")
            tags = data.get("tags") or []
            date_added = data.get("date_added", "unknown")

            evidence = [
                f"Threat: {threat}",
                f"Tags: {', '.join(tags) if tags else 'none'}",
                f"Date added: {date_added}",
                f"URL status: {url_status}",
            ]

            if url_status == "online":
                outcome = CheckOutcome(
                    status=CheckStatus.DONE,
                    severity=Severity.CRITICAL,
                    title="Active malware distribution URL",
                    detail=f"URL is active in URLhaus distributing malware ({threat}).",
                    evidence=evidence,
                    points=95,
                    signal="hard",
                    floor=95,
                    data={"urlhaus": data},
                )
            else:
                outcome = CheckOutcome(
                    status=CheckStatus.DONE,
                    severity=Severity.HIGH,
                    title="Known malware distribution URL (offline)",
                    detail=f"URL is cataloged in URLhaus as historical malware distribution ({threat}).",
                    evidence=evidence,
                    points=70,
                    signal="soft",
                    floor=70,
                    data={"urlhaus": data},
                )

        # 2. Not listed
        elif query_status == "no_results":
            outcome = CheckOutcome(
                status=CheckStatus.DONE,
                severity=Severity.INFO,
                title="Not listed in URLhaus",
                detail="URL was not found in the abuse.ch URLhaus malware database.",
                evidence=["No matching active or historical malware reports found in URLhaus."],
                points=0,
                signal="none",
                floor=None,
                data={"urlhaus": {"query_status": "no_results"}},
            )

        # 3. Any other query status is an error
        else:
            return CheckOutcome(
                status=CheckStatus.ERROR,
                severity=Severity.INFO,
                title="URLhaus error",
                detail=f"URLhaus API returned status: {query_status}",
                signal="none",
            )

        await cache.set(self.id.value, ctx.normalized_url, outcome)
        return outcome
