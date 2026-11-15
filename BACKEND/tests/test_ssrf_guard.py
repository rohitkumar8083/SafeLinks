"""Unit tests for SSRF Guard and DNS resolution protection."""

from unittest.mock import patch

import pytest

from app.core.errors import BlockedTargetError
from app.core.http_client import safe_fetch
from app.core.ssrf_guard import (
    ResolutionResult,
    validate_target_or_raise,
)


@pytest.mark.asyncio
async def test_blocked_ip_literals():
    blocked_hosts = [
        "127.0.0.1",
        "localhost",
        "10.0.0.1",
        "10.254.1.1",
        "172.16.0.5",
        "172.31.255.255",
        "192.168.1.1",
        "192.168.0.254",
        "169.254.169.254",
        "::1",
        "[::1]",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::ffff:169.254.169.254",
        "100.64.0.1",  # CGNAT
        "0.0.0.0",
    ]

    for host in blocked_hosts:
        with pytest.raises(BlockedTargetError):
            await validate_target_or_raise(host)


@pytest.mark.asyncio
async def test_hostname_resolving_to_private_ip():
    with patch(
        "app.core.ssrf_guard.resolve_host_ips",
        return_value=ResolutionResult(resolved_ips=["192.168.1.50"], dns_failed=False, error_message=None),
    ):
        with pytest.raises(BlockedTargetError) as exc_info:
            await validate_target_or_raise("internal-portal.corp")
        assert "resolved to blocked target IP" in exc_info.value.message


@pytest.mark.asyncio
async def test_public_ip_allowed():
    # 8.8.8.8 is a public DNS IP
    ips = await validate_target_or_raise("8.8.8.8")
    assert ips == ["8.8.8.8"]


@pytest.mark.asyncio
async def test_port_restrictions():
    # Only 80 and 443 are permitted
    with pytest.raises(BlockedTargetError):
        await validate_target_or_raise("8.8.8.8", port=22)

    with pytest.raises(BlockedTargetError):
        await validate_target_or_raise("8.8.8.8", port=8080)

    # 443 and 80 are allowed
    ips = await validate_target_or_raise("8.8.8.8", port=443)
    assert ips == ["8.8.8.8"]


@pytest.mark.asyncio
async def test_redirect_to_private_ip_is_blocked(respx_mock):
    # Public host 93.184.216.34 (example.com) redirects to metadata 169.254.169.254
    with patch(
        "app.core.http_client.validate_target_or_raise",
        side_effect=[
            ["93.184.216.34"],  # Hop 1 allowed
            BlockedTargetError("Target IP is blocked"),  # Hop 2 blocked!
        ],
    ):
        import httpx
        client = httpx.AsyncClient(transport=httpx.MockTransport(lambda req: httpx.Response(302, headers={"Location": "http://169.254.169.254/meta-data"})))

        with pytest.raises(BlockedTargetError):
            await safe_fetch("https://public-service.com/redirect", client=client)

        await client.aclose()
