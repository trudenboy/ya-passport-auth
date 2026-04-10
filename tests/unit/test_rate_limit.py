"""Tests for ``AsyncMinDelayLimiter``.

The limiter enforces a minimum wall-clock interval between successive
``acquire()`` calls. Everything is tested against a fake monotonic
clock + fake sleep so the suite stays deterministic and fast.
"""

from __future__ import annotations

import asyncio

import pytest

from ya_passport_auth.rate_limit import AsyncMinDelayLimiter


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        # Record the request and advance the clock deterministically.
        self.sleeps.append(seconds)
        if seconds > 0:
            self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


class TestAcquire:
    async def test_first_call_is_immediate(self, clock: FakeClock) -> None:
        limiter = AsyncMinDelayLimiter(
            min_interval_seconds=0.2,
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )
        await limiter.acquire()
        assert clock.sleeps == []
        assert clock.now == 0.0

    async def test_second_call_waits_full_interval(self, clock: FakeClock) -> None:
        limiter = AsyncMinDelayLimiter(
            min_interval_seconds=0.2,
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )
        await limiter.acquire()
        await limiter.acquire()
        assert clock.sleeps == [pytest.approx(0.2)]
        assert clock.now == pytest.approx(0.2)

    async def test_second_call_waits_remaining_interval(self, clock: FakeClock) -> None:
        limiter = AsyncMinDelayLimiter(
            min_interval_seconds=0.5,
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )
        await limiter.acquire()
        clock.now = 0.3  # 0.3s of external wall-clock elapsed
        await limiter.acquire()
        assert clock.sleeps == [pytest.approx(0.2)]
        assert clock.now == pytest.approx(0.5)

    async def test_no_wait_if_interval_already_passed(self, clock: FakeClock) -> None:
        limiter = AsyncMinDelayLimiter(
            min_interval_seconds=0.2,
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )
        await limiter.acquire()
        clock.now = 5.0  # a long time later
        await limiter.acquire()
        assert clock.sleeps == []

    async def test_sequential_acquires_stack_correctly(self, clock: FakeClock) -> None:
        limiter = AsyncMinDelayLimiter(
            min_interval_seconds=0.2,
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )
        for _ in range(4):
            await limiter.acquire()
        # First call free, three subsequent calls each wait 0.2s.
        assert clock.sleeps == [
            pytest.approx(0.2),
            pytest.approx(0.2),
            pytest.approx(0.2),
        ]
        assert clock.now == pytest.approx(0.6)


class TestConcurrency:
    async def test_concurrent_acquires_serialise(self) -> None:
        """Real event loop. Two coroutines racing on one limiter must
        observe a real-time gap of at least ``min_interval_seconds``."""
        limiter = AsyncMinDelayLimiter(min_interval_seconds=0.05)
        stamps: list[float] = []

        async def worker() -> None:
            await limiter.acquire()
            stamps.append(asyncio.get_event_loop().time())

        await asyncio.gather(worker(), worker(), worker())
        stamps.sort()
        assert stamps[1] - stamps[0] >= 0.04
        assert stamps[2] - stamps[1] >= 0.04


class TestConstruction:
    def test_rejects_non_positive_interval(self) -> None:
        with pytest.raises(ValueError, match="min_interval_seconds"):
            AsyncMinDelayLimiter(min_interval_seconds=0.0)
        with pytest.raises(ValueError, match="min_interval_seconds"):
            AsyncMinDelayLimiter(min_interval_seconds=-0.1)
