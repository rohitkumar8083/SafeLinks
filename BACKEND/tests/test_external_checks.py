"""Unit tests for external threat intelligence integrations using respx mocks."""

import httpx
import pytest
import respx

from app.config import Settings
from app.core.async_rate_limiter import (
    AsyncSlidingWindowRateLimiter,
    get_vt_rate_limiter,
    set_vt_rate_limiter,
)
from app.core.cache import get_threat_intel_cache
from app.schemas.scan import CheckStatus, ScanMode, Severity
from app.services.checks.google_safe_browsing import GoogleSafeBrowsingCheck
from app.services.checks.urlhaus import UrlhausCheck
from app.services.checks.virustotal import VirusTotalCheck, url_to_vt_id
from app.services.context import ScanContext
from app.services.url_normalizer import parse_and_normalize_url


def create_context(
    url: str,
    http_client: httpx.AsyncClient,
    gsb_key: str | None = None,
    vt_key: str | None = None,
    urlhaus_key: str | None = None,
) -> ScanContext:
    parsed = parse_and_normalize_url(url)
    cfg = Settings(
        GOOGLE_SAFE_BROWSING_API_KEY=gsb_key,
        VIRUSTOTAL_API_KEY=vt_key,
        URLHAUS_AUTH_KEY=urlhaus_key,
    )
    return ScanContext(
        scan_id="test-scan-ext",
        mode=ScanMode.FULL,
        submitted_url=url,
        normalized_url=parsed.normalized_url,
        parsed=parsed,
        settings=cfg,
        http_client=http_client,
    )


# =============================================================================
# Google Safe Browsing Tests
# =============================================================================


@pytest.mark.asyncio
async def test_gsb_missing_key():
    check = GoogleSafeBrowsingCheck()
    async with httpx.AsyncClient() as client:
        ctx = create_context("https://example.com", client, gsb_key=None)
        outcome = await check.run(ctx)
        assert outcome.status == CheckStatus.SKIPPED
        assert outcome.title == "Not configured"


@pytest.mark.asyncio
@respx.mock
async def test_gsb_clean_and_match():
    check = GoogleSafeBrowsingCheck()
    await get_threat_intel_cache().clear()

    # 1. No match (clean)
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    respx.post(endpoint).mock(return_value=httpx.Response(200, json={}))

    async with httpx.AsyncClient() as client:
        ctx_clean = create_context("https://example-clean.com", client, gsb_key="fake-gsb-key")
        out_clean = await check.run(ctx_clean)
        assert out_clean.status == CheckStatus.DONE
        assert out_clean.points == 0
        assert out_clean.severity == Severity.INFO
        assert out_clean.signal == "none"

    # 2. Match (flagged)
    respx.post(endpoint).mock(
        return_value=httpx.Response(
            200,
            json={
                "matches": [
                    {
                        "threatType": "SOCIAL_ENGINEERING",
                        "platformType": "ANY_PLATFORM",
                        "threat": {"url": "https://phishing-site.com"},
                    }
                ]
            },
        )
    )

    async with httpx.AsyncClient() as client:
        ctx_match = create_context("https://phishing-site.com", client, gsb_key="fake-gsb-key")
        out_match = await check.run(ctx_match)
        assert out_match.status == CheckStatus.DONE
        assert out_match.signal == "hard"
        assert out_match.floor == 92
        assert out_match.severity == Severity.CRITICAL
        assert any("SOCIAL_ENGINEERING" in ev for ev in out_match.evidence)


@pytest.mark.asyncio
@respx.mock
async def test_gsb_error_response():
    check = GoogleSafeBrowsingCheck()
    await get_threat_intel_cache().clear()
    respx.post("https://safebrowsing.googleapis.com/v4/threatMatches:find").mock(
        return_value=httpx.Response(403, json={"error": {"message": "Permission denied"}})
    )

    async with httpx.AsyncClient() as client:
        ctx = create_context("https://example-error.com", client, gsb_key="fake-key")
        outcome = await check.run(ctx)
        assert outcome.status == CheckStatus.ERROR
        assert outcome.title == "Google Safe Browsing error"


# =============================================================================
# VirusTotal Tests
# =============================================================================


@pytest.mark.asyncio
async def test_vt_missing_key():
    check = VirusTotalCheck()
    async with httpx.AsyncClient() as client:
        ctx = create_context("https://example.com", client, vt_key=None)
        outcome = await check.run(ctx)
        assert outcome.status == CheckStatus.SKIPPED
        assert outcome.title == "Not configured"


@pytest.mark.asyncio
@respx.mock
async def test_vt_existing_report_200():
    check = VirusTotalCheck()
    await get_threat_intel_cache().clear()
    await get_vt_rate_limiter().reset()

    url = "https://malicious-test.com"
    vt_id = url_to_vt_id("https://malicious-test.com/")
    api_url = f"https://www.virustotal.com/api/v3/urls/{vt_id}"

    respx.get(api_url).mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 8,
                            "suspicious": 2,
                            "harmless": 50,
                            "undetected": 10,
                        },
                        "last_analysis_results": {
                            "VendorA": {"category": "malicious", "result": "phishing"},
                            "VendorB": {"category": "malicious", "result": "trojan"},
                        },
                    }
                }
            },
        )
    )

    async with httpx.AsyncClient() as client:
        ctx = create_context(url, client, vt_key="fake-vt-key")
        outcome = await check.run(ctx)
        assert outcome.status == CheckStatus.DONE
        assert outcome.signal == "hard"
        assert outcome.floor == 90
        assert outcome.severity == Severity.CRITICAL  # >= 5 malicious
        assert any("10 of 70 engines" in ev for ev in outcome.evidence)


@pytest.mark.asyncio
@respx.mock
async def test_vt_submit_and_poll_404():
    check = VirusTotalCheck()
    await get_threat_intel_cache().clear()
    await get_vt_rate_limiter().reset()

    url = "https://new-url-sample.com"
    vt_id = url_to_vt_id("https://new-url-sample.com/")
    api_url = f"https://www.virustotal.com/api/v3/urls/{vt_id}"

    # 1. 404 on URL lookup
    respx.get(api_url).mock(return_value=httpx.Response(404))

    # 2. POST submission returns analysis ID
    respx.post("https://www.virustotal.com/api/v3/urls").mock(
        return_value=httpx.Response(200, json={"data": {"id": "analysis-12345"}})
    )

    # 3. Poll analysis endpoint returns completed
    respx.get("https://www.virustotal.com/api/v3/analyses/analysis-12345").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "status": "completed",
                        "stats": {"malicious": 0, "suspicious": 0, "harmless": 65, "undetected": 5},
                        "results": {},
                    }
                }
            },
        )
    )

    async with httpx.AsyncClient() as client:
        ctx = create_context(url, client, vt_key="fake-vt-key")
        outcome = await check.run(ctx)
        assert outcome.status == CheckStatus.DONE
        assert outcome.signal == "none"
        assert outcome.points == 0
        assert outcome.severity == Severity.INFO


@pytest.mark.asyncio
async def test_vt_quota_exhausted():
    check = VirusTotalCheck()
    await get_threat_intel_cache().clear()
    custom_limiter = AsyncSlidingWindowRateLimiter(requests_per_minute=1, requests_per_day=1)
    set_vt_rate_limiter(custom_limiter)
    try:
        # Exhaust daily quota
        assert await custom_limiter.acquire() is True

        async with httpx.AsyncClient() as client:
            ctx = create_context("https://quota-test.com", client, vt_key="fake-vt-key")
            outcome = await check.run(ctx)
            assert outcome.status == CheckStatus.SKIPPED
            assert "quota reached" in outcome.title.lower()
    finally:
        set_vt_rate_limiter(None)


# =============================================================================
# URLhaus Tests
# =============================================================================


@pytest.mark.asyncio
async def test_urlhaus_missing_key():
    check = UrlhausCheck()
    async with httpx.AsyncClient() as client:
        ctx = create_context("https://example.com", client, urlhaus_key=None)
        outcome = await check.run(ctx)
        assert outcome.status == CheckStatus.SKIPPED
        assert outcome.title == "Not configured"


@pytest.mark.asyncio
@respx.mock
async def test_urlhaus_listed_online():
    check = UrlhausCheck()
    await get_threat_intel_cache().clear()

    respx.post("https://urlhaus-api.abuse.ch/v1/url/").mock(
        return_value=httpx.Response(
            200,
            json={
                "query_status": "ok",
                "url_status": "online",
                "threat": "malware_download",
                "tags": ["AgentTesla", "executable"],
                "date_added": "2026-10-31 10:00:00 UTC",
            },
        )
    )

    async with httpx.AsyncClient() as client:
        ctx = create_context("http://bad-download.com/setup.exe", client, urlhaus_key="fake-key")
        outcome = await check.run(ctx)
        assert outcome.status == CheckStatus.DONE
        assert outcome.signal == "hard"
        assert outcome.floor == 95
        assert outcome.severity == Severity.CRITICAL
        assert any("AgentTesla" in ev for ev in outcome.evidence)


@pytest.mark.asyncio
@respx.mock
async def test_urlhaus_listed_offline():
    check = UrlhausCheck()
    await get_threat_intel_cache().clear()

    respx.post("https://urlhaus-api.abuse.ch/v1/url/").mock(
        return_value=httpx.Response(
            200,
            json={
                "query_status": "ok",
                "url_status": "offline",
                "threat": "malware_download",
                "tags": ["RedLineStealer"],
                "date_added": "2026-10-15 12:00:00 UTC",
            },
        )
    )

    async with httpx.AsyncClient() as client:
        ctx = create_context("http://old-malware.com/payload.bin", client, urlhaus_key="fake-key")
        outcome = await check.run(ctx)
        assert outcome.status == CheckStatus.DONE
        assert outcome.signal == "soft"
        assert outcome.floor == 70
        assert outcome.severity == Severity.HIGH


@pytest.mark.asyncio
@respx.mock
async def test_urlhaus_not_listed():
    check = UrlhausCheck()
    await get_threat_intel_cache().clear()

    respx.post("https://urlhaus-api.abuse.ch/v1/url/").mock(
        return_value=httpx.Response(200, json={"query_status": "no_results"})
    )

    async with httpx.AsyncClient() as client:
        ctx = create_context("https://clean-site.com", client, urlhaus_key="fake-key")
        outcome = await check.run(ctx)
        assert outcome.status == CheckStatus.DONE
        assert outcome.points == 0
        assert outcome.severity == Severity.INFO
        assert outcome.title == "Not listed in URLhaus"
