"""Unit tests for URL structure heuristics rules."""

import httpx
import pytest

from app.config import Settings
from app.schemas.scan import CheckStatus, ScanMode, Severity
from app.services.checks.url_structure import UrlStructureCheck
from app.services.context import ScanContext
from app.services.url_normalizer import parse_and_normalize_url


def build_ctx(url: str) -> ScanContext:
    parsed = parse_and_normalize_url(url)
    dummy_client = httpx.AsyncClient()
    return ScanContext(
        scan_id="test-scan-id",
        mode=ScanMode.FULL,
        submitted_url=url,
        normalized_url=parsed.normalized_url,
        parsed=parsed,
        settings=Settings(),
        http_client=dummy_client,
    )


@pytest.mark.asyncio
async def test_benign_url_scores_low():
    checker = UrlStructureCheck()
    ctx = build_ctx("https://www.google.com/search?q=fastapi")
    outcome = await checker.run(ctx)

    assert outcome.status == CheckStatus.DONE
    assert outcome.points == 0
    assert outcome.severity == Severity.INFO
    assert outcome.title == "URL looks normal"
    await ctx.http_client.aclose()


@pytest.mark.asyncio
async def test_obviously_malicious_url_scores_high():
    checker = UrlStructureCheck()
    # Combines userinfo, brand spoofing, suspicious keywords, risky TLD, plain http, custom port
    malicious_url = "http://admin@paypal.verification-portal-service.xyz:8080/secure/login/update?token=123"
    ctx = build_ctx(malicious_url)
    outcome = await checker.run(ctx)

    assert outcome.status == CheckStatus.DONE
    assert outcome.points >= 75
    assert outcome.severity == Severity.CRITICAL
    assert outcome.title == "Suspicious URL pattern"
    assert len(outcome.evidence) >= 4
    await ctx.http_client.aclose()


@pytest.mark.asyncio
async def test_rule_length():
    checker = UrlStructureCheck()

    # URL length > 75 and <= 120 -> +8
    url_medium = "https://example.com/" + "a" * 60
    ctx_med = build_ctx(url_medium)
    out_med = await checker.run(ctx_med)
    assert any("75" in ev for ev in out_med.evidence)
    await ctx_med.http_client.aclose()

    # URL length > 120 -> +15
    url_long = "https://example.com/" + "a" * 110
    ctx_long = build_ctx(url_long)
    out_long = await checker.run(ctx_long)
    assert any("120" in ev for ev in out_long.evidence)
    await ctx_long.http_client.aclose()


@pytest.mark.asyncio
async def test_rule_userinfo():
    checker = UrlStructureCheck()
    ctx = build_ctx("https://user:password@example.com/test")
    outcome = await checker.run(ctx)
    assert any("userinfo" in ev.lower() for ev in outcome.evidence)
    assert outcome.points >= 25
    await ctx.http_client.aclose()


@pytest.mark.asyncio
async def test_rule_ip_host():
    checker = UrlStructureCheck()
    ctx = build_ctx("https://93.184.216.34/index.html")
    outcome = await checker.run(ctx)
    assert any("IP address" in ev for ev in outcome.evidence)
    assert outcome.points >= 25
    await ctx.http_client.aclose()


@pytest.mark.asyncio
async def test_rule_subdomains():
    checker = UrlStructureCheck()

    # Exactly 3 labels -> +8
    ctx_3 = build_ctx("https://a.b.c.example.com/test")
    out_3 = await checker.run(ctx_3)
    assert any("3 subdomain labels" in ev for ev in out_3.evidence)
    await ctx_3.http_client.aclose()

    # 4 or more labels -> +15
    ctx_4 = build_ctx("https://a.b.c.d.example.com/test")
    out_4 = await checker.run(ctx_4)
    assert any("Excessive subdomain depth" in ev for ev in out_4.evidence)
    await ctx_4.http_client.aclose()


@pytest.mark.asyncio
async def test_rule_hyphens_in_domain():
    checker = UrlStructureCheck()

    # 1-2 hyphens -> +4
    ctx_2 = build_ctx("https://my-test.com/home")
    out_2 = await checker.run(ctx_2)
    assert any("hyphen(s)" in ev for ev in out_2.evidence)
    await ctx_2.http_client.aclose()

    # >= 3 hyphens -> +10
    ctx_3 = build_ctx("https://my-secure-login-portal.com/home")
    out_3 = await checker.run(ctx_3)
    assert any(">= 3" in ev for ev in out_3.evidence)
    await ctx_3.http_client.aclose()


@pytest.mark.asyncio
async def test_rule_punycode():
    checker = UrlStructureCheck()
    ctx = build_ctx("https://xn--e1afmkfd.de")
    outcome = await checker.run(ctx)
    assert any("punycode" in ev.lower() for ev in outcome.evidence)
    await ctx.http_client.aclose()


@pytest.mark.asyncio
async def test_rule_keywords():
    checker = UrlStructureCheck()
    # 'login' and 'verify' in host
    ctx = build_ctx("https://login-verify.example.com/account/billing")
    outcome = await checker.run(ctx)
    assert any("keyword" in ev.lower() for ev in outcome.evidence)
    await ctx.http_client.aclose()


@pytest.mark.asyncio
async def test_rule_url_shortener():
    checker = UrlStructureCheck()
    ctx = build_ctx("https://bit.ly/xyz123")
    outcome = await checker.run(ctx)
    assert any("shortening service" in ev.lower() for ev in outcome.evidence)
    await ctx.http_client.aclose()


@pytest.mark.asyncio
async def test_rule_risky_tld():
    checker = UrlStructureCheck()
    ctx = build_ctx("https://secure-portal.zip/")
    outcome = await checker.run(ctx)
    assert any("top-level domain (.zip)" in ev for ev in outcome.evidence)
    await ctx.http_client.aclose()


@pytest.mark.asyncio
async def test_rule_brand_spoofing():
    checker = UrlStructureCheck()
    # Brand 'paypal' in subdomain of unapproved domain
    ctx = build_ctx("https://paypal.attacker-site.com/signin")
    outcome = await checker.run(ctx)
    assert any("paypal" in ev.lower() and "attacker-site.com" in ev.lower() for ev in outcome.evidence)
    assert outcome.points >= 25
    await ctx.http_client.aclose()


@pytest.mark.asyncio
async def test_rule_digit_ratio():
    checker = UrlStructureCheck()
    ctx = build_ctx("https://server123456789.example.com/")
    outcome = await checker.run(ctx)
    assert any("digit ratio" in ev.lower() for ev in outcome.evidence)
    await ctx.http_client.aclose()


@pytest.mark.asyncio
async def test_rule_percent_encoding():
    checker = UrlStructureCheck()
    ctx = build_ctx("https://example.com/test?a=%20%21%22%23%24%25")
    outcome = await checker.run(ctx)
    assert any("percent-encoded" in ev.lower() for ev in outcome.evidence)
    await ctx.http_client.aclose()


@pytest.mark.asyncio
async def test_rule_plain_http():
    checker = UrlStructureCheck()
    ctx = build_ctx("http://example.com/")
    outcome = await checker.run(ctx)
    assert any("unencrypted HTTP" in ev for ev in outcome.evidence)
    await ctx.http_client.aclose()
