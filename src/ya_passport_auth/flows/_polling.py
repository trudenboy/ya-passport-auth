"""Generic polling driver shared by QR and device-code login flows.

Both flows have the same shape: call an endpoint at a fixed interval
until it either confirms (return the flow-specific payload) or the
local deadline elapses (raise a ``LoginTimeoutError`` subclass). The
device-code path additionally honors RFC 8628 §3.5 ``slow_down``
responses by bumping the interval and aborting if the bumped interval
would push the next poll past the deadline.

This module factors out timing, cancellation, and ``slow_down``
handling so per-flow modules only describe what one poll returns via
the :class:`PollResult` ADT.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from ya_passport_auth.exceptions import InvalidCredentialsError, LoginTimeoutError

__all__ = [
    "Confirmed",
    "Pending",
    "PollResult",
    "SlowDown",
    "drive_login",
]


@dataclass(frozen=True, slots=True)
class Pending:
    """Server has not confirmed yet — sleep one interval, then poll again."""


@dataclass(frozen=True, slots=True)
class SlowDown:
    """Server asks the client to back off (RFC 8628 §3.5).

    ``increment_s`` is added to the current poll interval. Subsequent
    polls use the new (higher) interval. SlowDown also acts like Pending
    in that the driver sleeps before the next poll.
    """

    increment_s: float


@dataclass(frozen=True, slots=True)
class Confirmed[T]:
    """Server confirmed; ``payload`` is the flow-specific result."""

    payload: T


type PollResult[T] = Pending | SlowDown | Confirmed[T]


async def drive_login[T](
    *,
    poll_one: Callable[[], Awaitable[PollResult[T]]],
    interval: float,
    total_timeout: float,
    timeout_exc: type[LoginTimeoutError],
    timeout_message: str,
    should_cancel: Callable[[], bool] | None = None,
) -> T:
    """Drive a polling login flow until confirmation or timeout.

    Args:
        poll_one: Awaitable returning one :class:`PollResult` per call.
        interval: Initial seconds between polls. Must be positive; the
            local variable is mutated when :class:`SlowDown` is returned.
        total_timeout: Seconds before raising ``timeout_exc``. Must be positive.
        timeout_exc: Concrete subclass of :class:`LoginTimeoutError`.
        timeout_message: Message for the timeout exception. When a
            :class:`SlowDown` push the next poll past the deadline, the
            suffix ``" after slow_down"`` is appended for diagnostics.
        should_cancel: Optional callback checked before each poll. When it
            returns truthy, :class:`InvalidCredentialsError` is raised
            with the message ``"login cancelled"``.

    Returns:
        The ``payload`` field of the first :class:`Confirmed` result.

    Raises:
        ValueError: ``interval`` or ``total_timeout`` is not strictly positive.
        InvalidCredentialsError: ``should_cancel`` returned truthy.
        timeout_exc: Local deadline expired before confirmation, or
            a :class:`SlowDown`-bumped interval would push the next poll
            past the deadline (RFC 8628 §3.5 forbids polling sooner).
    """
    if interval <= 0:
        raise ValueError("interval must be positive")
    if total_timeout <= 0:
        raise ValueError("total_timeout must be positive")

    deadline = time.monotonic() + total_timeout
    while True:
        if should_cancel is not None and should_cancel():
            raise InvalidCredentialsError("login cancelled")

        if time.monotonic() >= deadline:
            raise timeout_exc(timeout_message)

        result = await poll_one()
        if isinstance(result, Confirmed):
            return result.payload

        slowed = False
        if isinstance(result, SlowDown):
            interval += result.increment_s
            slowed = True

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise timeout_exc(timeout_message)
        if slowed and interval > remaining:
            # RFC 8628 §3.5: the client MUST honor the new interval.
            # If it exceeds the remaining budget, we cannot poll again
            # on time — abort rather than send one final too-fast poll.
            raise timeout_exc(f"{timeout_message} after slow_down")

        await asyncio.sleep(min(interval, remaining))
