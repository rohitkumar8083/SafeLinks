"""Shared HTTP client with SSRF guard, redirect handling, and payload caps."""

import logging
from typing import NamedTuple
from urllib.parse import urljoin, urlparse

import httpx

from app.constants import (
    DEFAULT_PORTS,
    DEFAULT_USER_AGENT,
    MAX_BODY_BYTES,
)
from app.core.errors import BlockedTargetError, UnsupportedSchemeError
from app.core.ssrf_guard import validate_target_or_raise

logger = logging.getLogger("safelinks.http")

_shared_client: httpx.AsyncClient | None = None


def get_shared_client() -> httpx.AsyncClient:
    """Returns the process-wide shared AsyncClient instance."""
    if _shared_client is None:
        raise RuntimeError("Shared AsyncClient has not been initialized in lifespan")
    return _shared_client


def set_shared_client(client: httpx.AsyncClient | None) -> None:
    """Sets or clears the shared client."""
    global _shared_client
    _shared_client = client


class RedirectHop(NamedTuple):
    status_code: int
    from_url: str
    to_url: str


class SafeFetchResult(NamedTuple):
    status_code: int | None
    headers: httpx.Headers | dict[str, str]
    content: bytes
    final_url: str
    hops: list[RedirectHop]
    dns_failed: bool
    unreachable: bool
    error: str | None


async def safe_fetch(
    url: str,
    client: httpx.AsyncClient | None = None,
    method: str = "GET",
    max_redirects: int = 5,
    timeout: float = 8.0,
    headers: dict[str, str] | None = None,
    head_only: bool = False,
) -> SafeFetchResult:
    """Fetches a URL with strict SSRF guarding, redirect tracking, and 64KB payload cap."""
    fetch_client = client or get_shared_client()
    current_url = url
    hops: list[RedirectHop] = []

    request_headers = {
        "User-Agent": DEFAULT_USER_AGENT,
        "Accept": "*/*",
        **(headers or {}),
    }

    for hop_idx in range(max_redirects + 1):
        parsed = urlparse(current_url)
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            raise UnsupportedSchemeError(f"Unsupported scheme '{scheme}' encountered during fetch")

        port = parsed.port or DEFAULT_PORTS.get(scheme)
        host = parsed.hostname
        if not host:
            raise BlockedTargetError("Target URL has no valid hostname")

        # SSRF Guard validation for current hop
        resolved_ips = await validate_target_or_raise(host, port)
        if not resolved_ips and host.lower() != "localhost":
            # DNS resolution failed for this host
            return SafeFetchResult(
                status_code=None,
                headers={},
                content=b"",
                final_url=current_url,
                hops=hops,
                dns_failed=True,
                unreachable=True,
                error=f"Domain '{host}' does not resolve",
            )

        try:
            req_method = "HEAD" if head_only and hop_idx == 0 else method
            request = fetch_client.build_request(
                req_method,
                current_url,
                headers=request_headers,
                timeout=timeout,
            )

            # Send request manually without automatic redirect following
            response = await fetch_client.send(request, stream=True)
            status = response.status_code

            # Handle 3xx Redirects
            if 300 <= status < 400 and "location" in response.headers:
                location = response.headers["location"]
                next_url = urljoin(current_url, location)
                hops.append(RedirectHop(status_code=status, from_url=current_url, to_url=next_url))
                await response.aclose()

                if hop_idx >= max_redirects:
                    # Exceeded redirect limit
                    return SafeFetchResult(
                        status_code=status,
                        headers=response.headers,
                        content=b"",
                        final_url=next_url,
                        hops=hops,
                        dns_failed=False,
                        unreachable=False,
                        error=f"Exceeded maximum redirect limit of {max_redirects} hops",
                    )

                current_url = next_url
                continue

            # Read up to MAX_BODY_BYTES (64KB)
            content_chunks: list[bytes] = []
            bytes_read = 0
            if not head_only:
                async for chunk in response.aiter_bytes():
                    needed = MAX_BODY_BYTES - bytes_read
                    if needed <= 0:
                        break
                    content_chunks.append(chunk[:needed])
                    bytes_read += len(chunk[:needed])

            await response.aclose()
            return SafeFetchResult(
                status_code=status,
                headers=response.headers,
                content=b"".join(content_chunks),
                final_url=current_url,
                hops=hops,
                dns_failed=False,
                unreachable=False,
                error=None,
            )

        except httpx.TimeoutException as e:
            return SafeFetchResult(
                status_code=None,
                headers={},
                content=b"",
                final_url=current_url,
                hops=hops,
                dns_failed=False,
                unreachable=True,
                error=f"Request timed out: {e}",
            )
        except httpx.RequestError as e:
            return SafeFetchResult(
                status_code=None,
                headers={},
                content=b"",
                final_url=current_url,
                hops=hops,
                dns_failed=False,
                unreachable=True,
                error=f"Connection failed: {e}",
            )

    return SafeFetchResult(
        status_code=None,
        headers={},
        content=b"",
        final_url=current_url,
        hops=hops,
        dns_failed=False,
        unreachable=True,
        error="Unknown redirect termination",
    )
