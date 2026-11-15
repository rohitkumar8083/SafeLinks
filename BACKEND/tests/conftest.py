"""Pytest fixtures and configuration."""

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from app.api.deps import set_repository
from app.config import Settings
from app.core.http_client import set_shared_client
from app.main import create_app
from app.repositories.scan_repo import InMemoryScanRepository


@pytest.fixture
def test_settings() -> Settings:
    return Settings(
        APP_NAME="SafeLinks API Test",
        ENVIRONMENT="dev",
        MAX_CONCURRENT_SCANS=10,
        CHECK_TIMEOUT_SECONDS=2.0,
        OVERALL_SCAN_TIMEOUT_SECONDS=5.0,
    )


@pytest_asyncio.fixture
async def test_repo() -> InMemoryScanRepository:
    repo = InMemoryScanRepository(max_stored_scans=100, ttl_minutes=10)
    set_repository(repo)
    yield repo
    set_repository(None)


@pytest_asyncio.fixture
async def async_client(test_settings: Settings, test_repo: InMemoryScanRepository) -> AsyncClient:
    app = create_app(test_settings)
    # Provide dummy shared client for offline test execution
    dummy_client = AsyncClient(transport=ASGITransport(app=app))
    set_shared_client(dummy_client)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        yield client

    set_shared_client(None)
    await dummy_client.aclose()
