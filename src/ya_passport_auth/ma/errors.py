"""Unified mapping of library exceptions onto Music Assistant error types.

Transient Passport failures (network, rate limiting) map to
``ResourceTemporarilyUnavailable`` so providers retry later instead of
clearing stored credentials; everything else maps to ``LoginFailed``.
Messages carry only the exception class name — library exception strings may
embed request bodies or token fragments that must not reach MA logs or the
frontend.
"""

from __future__ import annotations

from typing import NoReturn

from music_assistant_models.errors import LoginFailed, ResourceTemporarilyUnavailable

from ya_passport_auth.exceptions import (
    DeviceCodeTimeoutError,
    InvalidCredentialsError,
    NetworkError,
    QRTimeoutError,
    RateLimitedError,
    YaPassportError,
)

__all__ = ["failure_reason", "raise_mapped", "raise_mapped_refresh"]


def raise_mapped(err: YaPassportError, *, context: str) -> NoReturn:
    """Re-raise a library error as the matching Music Assistant error.

    Args:
        err: The ``ya_passport_auth`` exception to translate.
        context: Short human prefix for the message (e.g. ``"Device
            authentication"`` or ``"Failed to refresh music token"``).

    Raises:
        ResourceTemporarilyUnavailable: For transient failures (network,
            rate limit) — the caller should retry later and keep credentials.
        LoginFailed: For terminal credential failures.
    """
    if isinstance(err, NetworkError | RateLimitedError):
        raise ResourceTemporarilyUnavailable(
            f"{context}: Yandex Passport temporarily unavailable ({type(err).__name__})"
        ) from err
    if isinstance(err, QRTimeoutError | DeviceCodeTimeoutError):
        raise LoginFailed(f"{context} timed out. Please try again.") from err
    if isinstance(err, InvalidCredentialsError):
        raise LoginFailed(f"{context} was denied. Please try again.") from err
    raise LoginFailed(f"{context} failed ({type(err).__name__})") from err


def raise_mapped_refresh(err: YaPassportError, *, context: str) -> NoReturn:
    """Re-raise a library error from a silent token refresh/rotation.

    Unlike interactive login flows, a refresh acts on *stored* credentials —
    callers clear them on ``LoginFailed``. Only an explicit rejection
    (``InvalidCredentialsError``, e.g. OAuth ``invalid_grant``) proves the
    credential is dead; any other server response (including a novel OAuth
    error code during a Yandex incident) maps to
    ``ResourceTemporarilyUnavailable`` so a healthy token is never destroyed
    over a hiccup.

    Args:
        err: The ``ya_passport_auth`` exception to translate.
        context: Short human prefix for the message.

    Raises:
        LoginFailed: The credential was explicitly rejected.
        ResourceTemporarilyUnavailable: Anything else — retry later, keep
            credentials.
    """
    if isinstance(err, InvalidCredentialsError):
        raise LoginFailed(f"{context} was rejected. Please re-authenticate.") from err
    if isinstance(err, NetworkError | RateLimitedError):
        raise ResourceTemporarilyUnavailable(
            f"{context}: Yandex Passport temporarily unavailable ({type(err).__name__})"
        ) from err
    raise ResourceTemporarilyUnavailable(
        f"{context}: unexpected Yandex Passport response ({type(err).__name__}) — retry later"
    ) from err


def failure_reason(err: Exception) -> str:
    """Return the status-endpoint failure reason for a polling error.

    Args:
        err: The exception raised while polling for login confirmation.

    Returns:
        ``"expired"`` for a device-code timeout, ``"denied"`` for rejected
        credentials, ``"error"`` otherwise — the device-code page shows a
        matching terminal message.
    """
    if isinstance(err, DeviceCodeTimeoutError):
        return "expired"
    if isinstance(err, InvalidCredentialsError):
        return "denied"
    return "error"
