"""Contract verification tests ensuring field-for-field compliance with the shared API contract."""

import asyncio
from unittest.mock import patch

import httpx
import pytest
from httpx import AsyncClient

from app.constants import ORDERED_CHECK_IDS
from app.core.ssrf_guard import ResolutionResult


@pytest.mark.asyncio
async def test_health_contract(async_client: AsyncClient):
    resp = await async_client.get("/api/v1/health")
    assert resp.status_code == 200
    assert resp.headers.get("Cache-Control") == "no-store"
    assert resp.headers.get("X-Request-ID") is not None

    data = resp.json()
    assert data["status"] == "ok"
    assert isinstance(data["version"], str)
    assert isinstance(data["ml_model_loaded"], bool)


@pytest.mark.asyncio
async def test_full_scan_lifecycle_contract(async_client: AsyncClient):
    target_url = "https://example.com/test"

    from app.schemas.scan import CheckStatus, Severity
    from app.services.checks.base import CheckOutcome

    mock_age = CheckOutcome(
        status=CheckStatus.DONE,
        severity=Severity.INFO,
        title="Established domain",
        detail="Domain is 3000 days old",
        evidence=["Domain registered in 2000"],
        points=0,
        signal="soft",
        data={"domain": "example.com", "age_days": 3000, "registrar": "Example Registrar"},
    )
    mock_ssl = CheckOutcome(
        status=CheckStatus.DONE,
        severity=Severity.INFO,
        title="Valid SSL certificate",
        detail="Certificate is valid",
        evidence=["Issuer: DigiCert"],
        points=0,
        signal="soft",
        data={"ssl": {"valid": True, "issuer": "DigiCert", "expires_at": "2027-01-01T00:00:00Z", "days_remaining": 365}},
    )
    mock_redirect = CheckOutcome(
        status=CheckStatus.DONE,
        severity=Severity.INFO,
        title="Direct destination",
        detail="No redirects",
        evidence=["Direct 200 OK"],
        points=0,
        signal="soft",
        data={"hop_count": 0, "final_url": "https://example.com/test"},
    )

    # Mock DNS resolution to public IP so SSRF guard allows it
    with (
        patch(
            "app.core.ssrf_guard.resolve_host_ips",
            return_value=ResolutionResult(resolved_ips=["93.184.216.34"], dns_failed=False, error_message=None),
        ),
        patch("app.services.checks.domain_age.DomainAgeCheck.run", return_value=mock_age),
        patch("app.services.checks.ssl_certificate.SslCertificateCheck.run", return_value=mock_ssl),
        patch("app.services.checks.redirect_chain.RedirectChainCheck.run", return_value=mock_redirect),
    ):
        # 1. POST /scans returns 202
        post_resp = await async_client.post("/api/v1/scans", json={"url": target_url, "mode": "full"})
        assert post_resp.status_code == 202
        assert post_resp.headers.get("Cache-Control") == "no-store"
        assert post_resp.headers.get("X-Request-ID") is not None

        post_data = post_resp.json()
        assert "scan_id" in post_data
        assert post_data["status"] == "queued"
        assert post_data["submitted_url"] == target_url
        assert post_data["normalized_url"] == target_url

        scan_id = post_data["scan_id"]

        # 2. First poll GET /scans/{id}
        first_get = await async_client.get(f"/api/v1/scans/{scan_id}")
        assert first_get.status_code == 200
        first_data = first_get.json()

        # Contract Rule 1 & 2: All 8 checks present in exact order from the very first response
        assert len(first_data["checks"]) == 8
        check_ids = [c["id"] for c in first_data["checks"]]
        assert check_ids == list(ORDERED_CHECK_IDS)
        assert first_data["progress"]["total_checks"] == 8

        # Poll until scan completes
        final_data = None
        for _ in range(30):
            await asyncio.sleep(0.1)
            get_resp = await async_client.get(f"/api/v1/scans/{scan_id}")
            assert get_resp.status_code == 200
            current = get_resp.json()
            if current["status"] in ("completed", "failed"):
                final_data = current
                break

        assert final_data is not None
        assert final_data["status"] == "completed"
        assert final_data["error"] is None

        # Contract Rule 3: result is populated when completed
        assert final_data["result"] is not None
        assert 0 <= final_data["result"]["risk_score"] <= 100
        assert final_data["result"]["verdict"] in ("likely_safe", "suspicious", "likely_malicious", "unknown")
        assert 0.0 <= final_data["result"]["confidence"] <= 1.0
        assert isinstance(final_data["result"]["summary"], str)
        assert isinstance(final_data["result"]["recommendations"], list)

        # Datetimes format as UTC ISO strings ending in 'Z'
        assert final_data["created_at"].endswith("Z")
        assert final_data["completed_at"] is not None
        assert final_data["completed_at"].endswith("Z")

        # Progress total and completed count
        assert final_data["progress"]["total_checks"] == 8
        assert final_data["progress"]["completed_checks"] == 8


@pytest.mark.asyncio
async def test_quick_mode_skips_six_checks(async_client: AsyncClient):
    with patch(
        "app.core.ssrf_guard.resolve_host_ips",
        return_value=ResolutionResult(resolved_ips=["93.184.216.34"], dns_failed=False, error_message=None),
    ):
        post_resp = await async_client.post("/api/v1/scans", json={"url": "https://example.com/quick", "mode": "quick"})
        assert post_resp.status_code == 202
        scan_id = post_resp.json()["scan_id"]

        # Wait for completion
        for _ in range(30):
            await asyncio.sleep(0.1)
            get_resp = await async_client.get(f"/api/v1/scans/{scan_id}")
            data = get_resp.json()
            if data["status"] == "completed":
                break

        # In quick mode, the 6 checks must be skipped with 'Not run in quick mode'
        skipped_checks = [c for c in data["checks"] if c["detail"] == "Not run in quick mode"]
        assert len(skipped_checks) == 6
        for chk in skipped_checks:
            assert chk["status"] == "skipped"


@pytest.mark.asyncio
async def test_error_responses_contract(async_client: AsyncClient):
    # 1. 422 INVALID_URL (empty URL)
    resp_empty = await async_client.post("/api/v1/scans", json={"url": ""})
    assert resp_empty.status_code == 422
    data_empty = resp_empty.json()
    assert "error" in data_empty
    assert data_empty["error"]["code"] == "INVALID_URL"
    assert data_empty["error"]["request_id"] is not None

    # 2. 422 UNSUPPORTED_SCHEME (ftp)
    resp_ftp = await async_client.post("/api/v1/scans", json={"url": "ftp://example.com"})
    assert resp_ftp.status_code == 422
    data_ftp = resp_ftp.json()
    assert data_ftp["error"]["code"] == "UNSUPPORTED_SCHEME"

    # 3. 422 BLOCKED_TARGET (127.0.0.1)
    resp_blocked = await async_client.post("/api/v1/scans", json={"url": "http://127.0.0.1/admin"})
    assert resp_blocked.status_code == 422
    data_blocked = resp_blocked.json()
    assert data_blocked["error"]["code"] == "BLOCKED_TARGET"

    # 4. 404 NOT_FOUND (unknown scan id)
    resp_404 = await async_client.get("/api/v1/scans/non-existent-uuid-12345")
    assert resp_404.status_code == 404
    data_404 = resp_404.json()
    assert data_404["error"]["code"] == "NOT_FOUND"
    assert resp_404.headers.get("Cache-Control") == "no-store"


@pytest.mark.asyncio
async def test_full_scan_with_all_external_checks_active(async_client: AsyncClient):
    import respx

    from app.core.async_rate_limiter import get_vt_rate_limiter
    from app.core.cache import get_threat_intel_cache
    from app.schemas.scan import CheckStatus, Severity
    from app.services.checks.base import CheckOutcome
    from app.services.checks.virustotal import url_to_vt_id

    await get_threat_intel_cache().clear()
    await get_vt_rate_limiter().reset()

    target_url = "https://example-all-checks.com"
    norm_url = "https://example-all-checks.com/"
    vt_id = url_to_vt_id(norm_url)

    mock_age = CheckOutcome(
        status=CheckStatus.DONE,
        severity=Severity.INFO,
        title="Established domain",
        detail="Domain is 3000 days old",
        evidence=["Domain registered in 2000"],
        points=0,
        signal="soft",
        data={"domain": "example-all-checks.com", "age_days": 3000, "registrar": "Example Registrar"},
    )
    mock_ssl = CheckOutcome(
        status=CheckStatus.DONE,
        severity=Severity.INFO,
        title="Valid SSL certificate",
        detail="Certificate is valid",
        evidence=["Issuer: DigiCert"],
        points=0,
        signal="soft",
        data={"ssl": {"valid": True, "issuer": "DigiCert", "expires_at": "2027-01-01T00:00:00Z", "days_remaining": 365}},
    )
    mock_redirect = CheckOutcome(
        status=CheckStatus.DONE,
        severity=Severity.INFO,
        title="Direct destination",
        detail="No redirects",
        evidence=["Direct 200 OK"],
        points=0,
        signal="soft",
        data={"hop_count": 0, "final_url": norm_url},
    )

    with (
        patch(
            "app.core.ssrf_guard.resolve_host_ips",
            return_value=ResolutionResult(resolved_ips=["93.184.216.34"], dns_failed=False, error_message=None),
        ),
        patch("app.services.checks.domain_age.DomainAgeCheck.run", return_value=mock_age),
        patch("app.services.checks.ssl_certificate.SslCertificateCheck.run", return_value=mock_ssl),
        patch("app.services.checks.redirect_chain.RedirectChainCheck.run", return_value=mock_redirect),
    ):
        with respx.mock(assert_all_called=False):
            # Safe Browsing mock
            respx.post("https://safebrowsing.googleapis.com/v4/threatMatches:find").mock(
                return_value=httpx.Response(200, json={})
            )
            # VirusTotal mock
            respx.get(f"https://www.virustotal.com/api/v3/urls/{vt_id}").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "data": {
                            "attributes": {
                                "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 5},
                                "last_analysis_results": {},
                            }
                        }
                    },
                )
            )
            # URLhaus mock
            respx.post("https://urlhaus-api.abuse.ch/v1/url/").mock(
                return_value=httpx.Response(200, json={"query_status": "no_results"})
            )

            # Submit scan
            post_resp = await async_client.post("/api/v1/scans", json={"url": target_url, "mode": "full"})
            assert post_resp.status_code == 202
            scan_id = post_resp.json()["scan_id"]

            # Poll until completed
            final_data = None
            for _ in range(30):
                await asyncio.sleep(0.1)
                get_resp = await async_client.get(f"/api/v1/scans/{scan_id}")
                current = get_resp.json()
                if current["status"] in ("completed", "failed"):
                    final_data = current
                    break

            assert final_data is not None
            assert final_data["status"] == "completed"
            assert final_data["result"] is not None
            assert final_data["result"]["verdict"] in ("likely_safe", "suspicious", "likely_malicious")
            assert final_data["progress"]["completed_checks"] == 8
            assert final_data["progress"]["total_checks"] == 8
            # Check domain_info and ml result blocks
            assert final_data["result"]["domain_info"] is not None
            assert final_data["result"]["domain_info"]["domain"] == "example-all-checks.com"
