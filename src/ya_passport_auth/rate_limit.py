"""Minimum-delay async rate limiter.

Yandex Passport endpoints will throttle (HTTP 429) and, more
aggressively, ban IPs that burst through their unpublished per-client
quota. Every outgoing request from this library is therefore gated on
an :class:`AsyncMinDelayLimiter` that enforces a minimum interval
between successive acquires.

The limiter is deliberately boring: no token buckets, no jitter. The
goal is to keep the library well below the "normal user" threshold,
not to squeeze out maximum throughput.

``monotonic`` and ``sleep`` are injectable so tests can drive the
limiter with a fake clock and assert exact waits without real sleeps.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable

__all__ = ["AsyncMinDelayLimiter"]


MonotonicFn = Callable[[], float]
SleepFn = Callable[[float], Awaitable[None]]


class AsyncMinDelayLimiter:
    """Serialize calls with a minimum inter-call interval.

    Consecutive ``acquire()`` calls are guaranteed to be at least
    ``min_interval_seconds`` apart. Not a per-host limiter — instantiate
    one per host if needed. For this library one instance per
    :class:`PassportClient` is enough because every endpoint is on a
    Yandex subdomain.
    """

    __slots__ = ("_last", "_lock", "_min_interval", "_monotonic", "_sleep")

    def __init__(
        self,
        min_interval_seconds: float,
        *,
        monotonic: MonotonicFn | None = None,
        sleep: SleepFn | None = None,
    ) -> None:
        if min_interval_seconds <= 0:
            raise ValueError(
                f"AsyncMinDelayLimiter.min_interval_seconds must be > 0, "
                f"got {min_interval_seconds!r}",
            )
        self._min_interval = min_interval_seconds
        self._monotonic: MonotonicFn = monotonic or time.monotonic
        self._sleep: SleepFn = sleep or asyncio.sleep
        self._last: float | None = None
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Block until the minimum interval has elapsed.

        Returns only once at least ``min_interval_seconds`` have passed
        since the previous ``acquire()`` call returned.
        """
        async with self._lock:
            now = self._monotonic()
            if self._last is not None:
                wait = self._min_interval - (now - self._last)
                if wait > 0:
                    await self._sleep(wait)
                    now = self._monotonic()
            self._last = now
