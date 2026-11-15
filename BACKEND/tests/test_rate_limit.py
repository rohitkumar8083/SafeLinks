"""Unit tests for SlowAPI client IP rate limiting."""

from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.api.deps import set_repository
from app.config import Settings
from app.core.http_client import set_shared_client
from app.core.rate_limit import limiter
from app.core.ssrf_guard import ResolutionResult
from app.main import create_app
from app.repositories.scan_repo import InMemoryScanRepository


@pytest.mark.asyncio
async def test_scan_rate_limiting_triggers_429():
    test_settings = Settings(
        RATE_LIMIT_SCANS_PER_MINUTE=3,
        RATE_LIMIT_READS_PER_MINUTE=10,
    )
    repo = InMemoryScanRepository()
    set_repository(repo)

    # Reset limiter storage
    limiter.reset()

    app = create_app(test_settings)
    dummy_client = AsyncClient(transport=ASGITransport(app=app))
    set_shared_client(dummy_client)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        with (
            patch("app.api.v1.routes_scans.settings", test_settings),
            patch(
                "app.core.ssrf_guard.resolve_host_ips",
                return_value=ResolutionResult(resolved_ips=["93.184.216.34"], dns_failed=False, error_message=None),
            ),
        ):
            # First 3 requests should be accepted
            for i in range(3):
                resp = await client.post("/api/v1/scans", json={"url": f"https://example.com/test-{i}", "mode": "quick"})
                assert resp.status_code == 202

            # 4th request should exceed the 3/minute limit and return 429
            resp_4th = await client.post("/api/v1/scans", json={"url": "https://example.com/test-exceeded", "mode": "quick"})
            assert resp_4th.status_code == 429
            assert resp_4th.headers.get("Cache-Control") == "no-store"
            assert resp_4th.headers.get("X-Request-ID") is not None

            data = resp_4th.json()
            assert "error" in data
            assert data["error"]["code"] == "RATE_LIMITED"
            assert data["error"]["request_id"] is not None

    set_repository(None)
    set_shared_client(None)
    await dummy_client.aclose()
