"""In-memory TTL cache for external threat intelligence checks using cachetools."""

import asyncio

from cachetools import TTLCache

from app.schemas.scan import CheckStatus
from app.services.checks.base import CheckOutcome


class ThreatIntelCache:
    """Thread-safe asynchronous TTL cache for check outcomes keyed by (check_id, normalized_url)."""

    def __init__(self, maxsize: int = 10000, ttl_seconds: int = 3600) -> None:
        self._ttl_seconds = ttl_seconds
        self._cache: TTLCache[tuple[str, str], CheckOutcome] = TTLCache(maxsize=maxsize, ttl=ttl_seconds)
        self._lock = asyncio.Lock()

    async def get(self, check_id: str, normalized_url: str) -> CheckOutcome | None:
        """Retrieves cached outcome if present and not expired."""
        key = (check_id, normalized_url)
        async with self._lock:
            return self._cache.get(key)

    async def set(self, check_id: str, normalized_url: str, outcome: CheckOutcome) -> None:
        """Caches only successful check outcomes."""
        if outcome.status != CheckStatus.DONE:
            return
        key = (check_id, normalized_url)
        async with self._lock:
            self._cache[key] = outcome

    async def clear(self) -> None:
        """Clears all cached entries (useful for testing)."""
        async with self._lock:
            self._cache.clear()


# Process-wide shared threat intelligence cache instance
_shared_threat_cache: ThreatIntelCache | None = None


def get_threat_intel_cache(ttl_seconds: int = 3600) -> ThreatIntelCache:
    global _shared_threat_cache
    if _shared_threat_cache is None:
        _shared_threat_cache = ThreatIntelCache(ttl_seconds=ttl_seconds)
    return _shared_threat_cache
