"""Asynchronous rate limiter with sliding-window minute limits and UTC-day counters."""

import asyncio
import time
from datetime import UTC, datetime


class AsyncSlidingWindowRateLimiter:
    """Sliding-window rate limiter tracking requests per minute and requests per UTC day."""

    def __init__(self, requests_per_minute: int = 4, requests_per_day: int = 500) -> None:
        self.requests_per_minute = requests_per_minute
        self.requests_per_day = requests_per_day

        self._lock = asyncio.Lock()
        self._minute_timestamps: list[float] = []
        self._current_utc_day: str = datetime.now(UTC).strftime("%Y-%m-%d")
        self._daily_request_count: int = 0

    async def acquire(self, max_wait_seconds: float = 0.0) -> bool:
        """Attempts to acquire a rate limit slot.

        If the minute rate is full but wait_time <= max_wait_seconds, sleeps and acquires.
        Returns False if day quota or minute quota (without sufficient wait) is exhausted.
        """
        async with self._lock:
            now = time.time()
            today_str = datetime.now(UTC).strftime("%Y-%m-%d")

            # Reset daily counter on UTC day boundary
            if today_str != self._current_utc_day:
                self._current_utc_day = today_str
                self._daily_request_count = 0

            # Daily quota check
            if self._daily_request_count >= self.requests_per_day:
                return False

            # Prune minute sliding window
            self._minute_timestamps = [ts for ts in self._minute_timestamps if now - ts < 60.0]

            # Check minute capacity
            if len(self._minute_timestamps) >= self.requests_per_minute:
                oldest_ts = self._minute_timestamps[0]
                wait_needed = 60.0 - (now - oldest_ts) + 0.05
                if 0 < wait_needed <= max_wait_seconds:
                    # Sleep outside lock or after updating
                    pass
                else:
                    return False

            # If wait was needed within allowable threshold
            if len(self._minute_timestamps) >= self.requests_per_minute:
                oldest_ts = self._minute_timestamps[0]
                wait_needed = 60.0 - (now - oldest_ts) + 0.05
                if 0 < wait_needed <= max_wait_seconds:
                    await asyncio.sleep(wait_needed)
                    now = time.time()
                    self._minute_timestamps = [ts for ts in self._minute_timestamps if now - ts < 60.0]

            self._minute_timestamps.append(now)
            self._daily_request_count += 1
            return True

    async def reset(self) -> None:
        """Resets the limiter counters (useful for testing)."""
        async with self._lock:
            self._minute_timestamps.clear()
            self._daily_request_count = 0


# Shared limiter for VirusTotal
_shared_vt_limiter: AsyncSlidingWindowRateLimiter | None = None


def set_vt_rate_limiter(limiter: AsyncSlidingWindowRateLimiter | None) -> None:
    global _shared_vt_limiter
    _shared_vt_limiter = limiter


def get_vt_rate_limiter(requests_per_minute: int = 4, requests_per_day: int = 500) -> AsyncSlidingWindowRateLimiter:
    global _shared_vt_limiter
    if _shared_vt_limiter is None:
        _shared_vt_limiter = AsyncSlidingWindowRateLimiter(
            requests_per_minute=requests_per_minute,
            requests_per_day=requests_per_day,
        )
    return _shared_vt_limiter
