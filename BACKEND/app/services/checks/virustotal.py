"""VirusTotal v3 malware and reputation check with rate limiting and analysis polling."""

import asyncio
import base64
import logging

from app.core.async_rate_limiter import get_vt_rate_limiter
from app.core.cache import get_threat_intel_cache
from app.schemas.scan import CheckCategory, CheckId, CheckStatus, Severity
from app.services.checks.base import BaseCheck, CheckOutcome
from app.services.context import ScanContext

logger = logging.getLogger("safelinks.checks.virustotal")


def url_to_vt_id(url: str) -> str:
    """Converts a URL to its URL-safe base64 VirusTotal identifier without '=' padding."""
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


class VirusTotalCheck(BaseCheck):
    """Multi-engine security inspection against VirusTotal v3 API."""

    id = CheckId.VIRUSTOTAL
    name = "VirusTotal"
    category = CheckCategory.MALWARE
    source = "VirusTotal v3 API"
    runs_in_quick_mode = False

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        api_key = ctx.settings.VIRUSTOTAL_API_KEY
        if not api_key:
            return CheckOutcome(
                status=CheckStatus.SKIPPED,
                severity=Severity.INFO,
                title="Not configured",
                detail="This check needs an API key on the server.",
                evidence=["VirusTotal API key was not configured on this instance."],
                signal="none",
            )

        cache = get_threat_intel_cache(ttl_seconds=ctx.settings.CACHE_TTL_SECONDS)
        cached = await cache.get(self.id.value, ctx.normalized_url)
        if cached:
            return cached

        limiter = get_vt_rate_limiter(
            requests_per_minute=ctx.settings.VT_REQUESTS_PER_MINUTE,
            requests_per_day=ctx.settings.VT_REQUESTS_PER_DAY,
        )

        headers = {
            "x-apikey": api_key,
            "Accept": "application/json",
        }

        url_id = url_to_vt_id(ctx.normalized_url)
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        # 1. Acquire slot for GET request
        can_proceed = await limiter.acquire(max_wait_seconds=5.0)
        if not can_proceed:
            return CheckOutcome(
                status=CheckStatus.SKIPPED,
                severity=Severity.INFO,
                title="VirusTotal quota reached",
                detail="VirusTotal quota reached, try again later",
                evidence=["API rate limit capacity reached."],
                signal="none",
            )

        stats: dict[str, int] = {}
        engine_details: list[str] = []

        try:
            resp = await ctx.http_client.get(api_url, headers=headers, timeout=10.0)

            # 2. Existing analysis report found
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                results = attributes.get("last_analysis_results", {})

                for engine, info in results.items():
                    cat = info.get("category")
                    if cat in ("malicious", "suspicious"):
                        engine_details.append(f"{engine}: {info.get('result', cat)}")

            # 3. Not found (404) -> Submit URL for scan and poll
            elif resp.status_code == 404:
                # Need another rate limit slot for submission
                can_post = await limiter.acquire(max_wait_seconds=5.0)
                if not can_post:
                    return CheckOutcome(
                        status=CheckStatus.SKIPPED,
                        severity=Severity.INFO,
                        title="VirusTotal quota reached",
                        detail="VirusTotal quota reached, try again later",
                        signal="none",
                    )

                submit_resp = await ctx.http_client.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": ctx.normalized_url},
                    timeout=10.0,
                )
                if submit_resp.status_code not in (200, 201):
                    return CheckOutcome(
                        status=CheckStatus.ERROR,
                        severity=Severity.INFO,
                        title="VirusTotal submission error",
                        detail="Could not submit URL to VirusTotal for analysis.",
                        signal="none",
                    )

                analysis_id = submit_resp.json().get("data", {}).get("id")
                if not analysis_id:
                    return CheckOutcome(
                        status=CheckStatus.SKIPPED,
                        severity=Severity.INFO,
                        title="VirusTotal pending",
                        detail="VirusTotal is still analysing this URL",
                        signal="none",
                    )

                # Poll up to 2 times
                poll_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                completed = False
                for _ in range(2):
                    await asyncio.sleep(min(3.0, ctx.settings.VT_MAX_WAIT_SECONDS))
                    can_poll = await limiter.acquire(max_wait_seconds=3.0)
                    if not can_poll:
                        break

                    poll_resp = await ctx.http_client.get(poll_url, headers=headers, timeout=10.0)
                    if poll_resp.status_code == 200:
                        poll_data = poll_resp.json().get("data", {})
                        poll_attrs = poll_data.get("attributes", {})
                        if poll_attrs.get("status") == "completed":
                            stats = poll_attrs.get("stats", {})
                            results = poll_attrs.get("results", {})
                            for engine, info in results.items():
                                cat = info.get("category")
                                if cat in ("malicious", "suspicious"):
                                    engine_details.append(f"{engine}: {info.get('result', cat)}")
                            completed = True
                            break

                if not completed:
                    return CheckOutcome(
                        status=CheckStatus.SKIPPED,
                        severity=Severity.INFO,
                        title="VirusTotal analysis pending",
                        detail="VirusTotal is still analysing this URL",
                        evidence=["Analysis is queued or running in VirusTotal cloud."],
                        signal="none",
                    )
            elif resp.status_code == 429:
                return CheckOutcome(
                    status=CheckStatus.SKIPPED,
                    severity=Severity.INFO,
                    title="VirusTotal quota reached",
                    detail="VirusTotal quota reached, try again later",
                    signal="none",
                )
            else:
                return CheckOutcome(
                    status=CheckStatus.ERROR,
                    severity=Severity.INFO,
                    title="VirusTotal error",
                    detail="VirusTotal service returned an error status.",
                    signal="none",
                )

        except Exception as e:
            logger.warning("VirusTotal request failed: %s", e)
            return CheckOutcome(
                status=CheckStatus.ERROR,
                severity=Severity.INFO,
                title="VirusTotal error",
                detail="VirusTotal service communication failed.",
                signal="none",
            )

        # 4. Score and format results
        total_engines = sum(stats.values()) if stats else 0
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        evidence: list[str] = []
        if (malicious + suspicious) > 0:
            evidence.append(f"{malicious + suspicious} of {total_engines} engines flagged this URL")
            evidence.extend(engine_details[:5])
        else:
            evidence.append(f"0 of {total_engines} engines flagged this URL")

        # malicious of 3 or more = HARD signal with floor 90 (floor 95 when 10 or more)
        if malicious >= 3:
            floor = 95 if malicious >= 10 else 90
            points = floor
            severity = Severity.CRITICAL if malicious >= 5 else Severity.HIGH
            title = "VirusTotal security alert"
            detail = f"{malicious} of {total_engines} security vendors flagged this URL as malicious."
            outcome = CheckOutcome(
                status=CheckStatus.DONE,
                severity=severity,
                title=title,
                detail=detail,
                evidence=evidence,
                points=points,
                signal="hard",
                floor=floor,
                data={"stats": stats},
            )
        # malicious 1-2 or suspicious >= 1 = soft, points 40 (60 when both), severity medium
        elif malicious in (1, 2) or suspicious >= 1:
            points = 60 if (malicious > 0 and suspicious > 0) else 40
            title = "VirusTotal suspicious detection"
            detail = f"{malicious} malicious and {suspicious} suspicious detection(s) among {total_engines} engines."
            outcome = CheckOutcome(
                status=CheckStatus.DONE,
                severity=Severity.MEDIUM,
                title=title,
                detail=detail,
                evidence=evidence,
                points=points,
                signal="soft",
                floor=None,
                data={"stats": stats},
            )
        # otherwise info with '0 of N engines flagged this URL'
        else:
            outcome = CheckOutcome(
                status=CheckStatus.DONE,
                severity=Severity.INFO,
                title="Clean on VirusTotal",
                detail=f"0 of {total_engines} engines flagged this URL",
                evidence=evidence,
                points=0,
                signal="none",
                floor=None,
                data={"stats": stats},
            )

        await cache.set(self.id.value, ctx.normalized_url, outcome)
        return outcome
