"""Manual redirect chain crawler with per-hop SSRF validation and risk evaluation."""

import ipaddress
import logging
from urllib.parse import urljoin, urlparse

import httpx
import tldextract

from app.constants import DEFAULT_USER_AGENT
from app.core.errors import BlockedTargetError
from app.core.ssrf_guard import validate_target_or_raise
from app.schemas.scan import CheckCategory, CheckId, CheckStatus, Severity
from app.services.checks.base import BaseCheck, CheckOutcome
from app.services.context import ScanContext

logger = logging.getLogger("safelinks.checks.redirects")

_tld_extractor = tldextract.TLDExtract(cache_dir=False, suffix_list_urls=None, include_psl_private_domains=True)


class RedirectChainCheck(BaseCheck):
    """Crawls HTTP redirect hops manually, enforcing SSRF and detecting evasion patterns."""

    id = CheckId.REDIRECT_CHAIN
    name = "Redirect chain"
    category = CheckCategory.URL_STRUCTURE
    source = "SafeLinks crawler"
    runs_in_quick_mode = False

    async def run(self, ctx: ScanContext) -> CheckOutcome:
        current_url = ctx.normalized_url
        submitted_reg_domain = ctx.parsed.registered_domain
        points = 0
        evidence: list[str] = []
        hop_count = 0
        cross_domain_points = 0
        exceeded_limit = False
        client = ctx.http_client

        headers = {
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": "*/*",
        }

        # Follow redirects manually up to 5 hops
        for _ in range(5):
            parsed_current = urlparse(current_url)
            scheme = parsed_current.scheme.lower()
            if scheme not in ("http", "https"):
                break

            port = parsed_current.port or (80 if scheme == "http" else 443)
            host = parsed_current.hostname
            if not host:
                break

            # Validate target with SSRF guard on EVERY hop
            try:
                resolved_ips = await validate_target_or_raise(host, port)
                if not resolved_ips and host.lower() != "localhost":
                    # Site did not resolve
                    return CheckOutcome(
                        status=CheckStatus.DONE,
                        severity=Severity.LOW,
                        title="Site did not respond",
                        detail="The site did not respond (it may be offline or blocking scanners)",
                        evidence=[f"Host '{host}' could not be resolved during redirect crawl."],
                        points=10,
                        signal="soft",
                    )
            except BlockedTargetError as e:
                # Redirecting into a private or blocked network is critical
                return CheckOutcome(
                    status=CheckStatus.DONE,
                    severity=Severity.CRITICAL,
                    title="Redirect to blocked network",
                    detail=f"Redirect chain attempted to navigate to a blocked target: {e.message}",
                    evidence=[f"Blocked target encountered: {e.message}"],
                    points=100,
                    signal="soft",
                )

            # Perform HEAD first, fallback to GET (streaming and closed immediately)
            response: httpx.Response | None = None
            try:
                try:
                    response = await client.head(current_url, headers=headers, timeout=5.0, follow_redirects=False)
                    # If server returns 405 Method Not Allowed or 403 on HEAD, try GET
                    if response.status_code in (403, 405):
                        await response.aclose()
                        response = None
                except Exception:
                    response = None

                if response is None:
                    # Stream GET and close immediately without reading body
                    req = client.build_request("GET", current_url, headers=headers, timeout=5.0)
                    response = await client.send(req, stream=True)

                status_code = response.status_code

                # If 3xx redirect
                if 300 <= status_code < 400 and "location" in response.headers:
                    hop_count += 1
                    raw_location = response.headers["location"]
                    next_url = urljoin(current_url, raw_location)
                    evidence.append(f"{status_code} {current_url} -> {next_url}")
                    await response.aclose()

                    # Analyze redirect transition
                    parsed_next = urlparse(next_url)
                    next_host = parsed_next.hostname or ""
                    next_scheme = parsed_next.scheme.lower()

                    # 1. Check HTTPS to HTTP downgrade (+25)
                    if scheme == "https" and next_scheme == "http":
                        points += 25
                        evidence.append("Security downgrade: Redirected from secure HTTPS to unencrypted HTTP")

                    # 2. Check redirect to an IP host (+30)
                    try:
                        ipaddress.ip_address(next_host.strip("[]"))
                        points += 30
                        evidence.append(f"Redirected to direct IP host address ({next_host})")
                    except ValueError:
                        pass

                    # 3. Check cross-registered-domain hop (+20, capped at 50)
                    ext_current = _tld_extractor(host)
                    ext_next = _tld_extractor(next_host)
                    current_reg = getattr(ext_current, "top_domain_under_public_suffix", None) or ext_current.registered_domain or host
                    next_reg = getattr(ext_next, "top_domain_under_public_suffix", None) or ext_next.registered_domain or next_host
                    if current_reg.lower() != next_reg.lower():
                        if cross_domain_points < 50:
                            added = min(20, 50 - cross_domain_points)
                            cross_domain_points += added
                            points += added
                            evidence.append(f"Cross-domain redirect from '{current_reg}' to '{next_reg}' (+{added})")

                    current_url = next_url
                    continue
                else:
                    await response.aclose()
                    break

            except (httpx.TimeoutException, httpx.RequestError):
                if hop_count == 0:
                    return CheckOutcome(
                        status=CheckStatus.DONE,
                        severity=Severity.LOW,
                        title="Site did not respond",
                        detail="The site did not respond (it may be offline or blocking scanners)",
                        evidence=["Initial HTTP request failed or timed out."],
                        points=10,
                        signal="soft",
                    )
                # Failed mid-chain
                break

        else:
            # Loop ended without break -> hit 5 hops limit
            exceeded_limit = True

        # Point modifiers for overall chain:
        # Exceeding the limit (+30)
        if exceeded_limit:
            points += 30
            evidence.append("Redirect chain exceeded the maximum safety limit of 5 hops")
        elif hop_count > 3:
            # More than 3 hops (+15)
            points += 15
            evidence.append(f"Elevated redirect hop count ({hop_count} hops > 3)")

        # Final registered domain differing from submitted one (+10)
        final_parsed = urlparse(current_url)
        final_host = final_parsed.hostname or ""
        ext_final = _tld_extractor(final_host)
        final_reg = getattr(ext_final, "top_domain_under_public_suffix", None) or ext_final.registered_domain or final_host
        if submitted_reg_domain and final_reg and submitted_reg_domain.lower() != final_reg.lower():
            points += 10
            evidence.append(
                f"Destination domain '{final_reg}' differs from originally submitted domain '{submitted_reg_domain}'"
            )

        final_points = min(100, points)

        if final_points < 15:
            severity = Severity.INFO
        elif final_points < 35:
            severity = Severity.LOW
        elif final_points < 55:
            severity = Severity.MEDIUM
        elif final_points < 75:
            severity = Severity.HIGH
        else:
            severity = Severity.CRITICAL

        title = "Suspicious redirect chain" if final_points >= 35 else "Normal redirect behavior"
        if not evidence:
            detail = "No redirects were encountered; destination resolved directly."
        else:
            detail = f"Followed {hop_count} redirect hop(s) with total risk score {final_points}."

        return CheckOutcome(
            status=CheckStatus.DONE,
            severity=severity,
            title=title,
            detail=detail,
            evidence=evidence,
            points=final_points,
            signal="soft",
            data={"hop_count": hop_count, "final_url": current_url},
        )
