"""Token-maintenance helpers with unified MA error mapping.

Thin wrappers over :class:`ya_passport_auth.PassportClient` that translate
library exceptions into Music Assistant error types (see
:mod:`ya_passport_auth.ma.errors`): transient Passport failures surface as
``ResourceTemporarilyUnavailable`` so callers retry later instead of
clearing stored credentials.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ya_passport_auth import Credentials, PassportClient
from ya_passport_auth.exceptions import NetworkError, RateLimitedError, YaPassportError

from .errors import raise_mapped_refresh

if TYPE_CHECKING:
    from ya_passport_auth import SecretStr

__all__ = ["refresh_credentials", "refresh_music_token", "validate_x_token"]


async def refresh_music_token(x_token: SecretStr) -> SecretStr:
    """Exchange an x_token for a fresh music-scoped OAuth token.

    Args:
        x_token: Long-lived Yandex Passport session token.

    Returns:
        A fresh music-scoped OAuth token.

    Raises:
        ResourceTemporarilyUnavailable: Transient or unrecognized failure —
            retry later, keep stored credentials.
        LoginFailed: The x_token was explicitly rejected (expired/invalid).
    """
    try:
        async with PassportClient.create() as client:
            return await client.refresh_music_token(x_token)
    except YaPassportError as err:
        raise_mapped_refresh(err, context="Music token refresh")


async def refresh_credentials(x_token: SecretStr, refresh_token: SecretStr) -> Credentials:
    """Silently re-issue the full credential triple using a refresh token.

    Only available for accounts authenticated via the Device Flow (QR and
    cookie logins do not yield a ``refresh_token``). Rotates both
    ``x_token`` and ``refresh_token`` server-side, so callers MUST persist
    the returned credentials.

    Args:
        x_token: Current long-lived Yandex Passport session token.
        refresh_token: Refresh token issued during Device Flow.

    Returns:
        New credentials with rotated ``x_token`` and ``refresh_token``.

    Raises:
        ResourceTemporarilyUnavailable: Transient or unrecognized failure —
            retry later, keep stored credentials.
        LoginFailed: The refresh token was explicitly rejected
            (``invalid_grant``).
    """
    try:
        async with PassportClient.create() as client:
            return await client.refresh_credentials(
                Credentials(x_token=x_token, refresh_token=refresh_token)
            )
    except YaPassportError as err:
        raise_mapped_refresh(err, context="Credential refresh")


async def validate_x_token(x_token: SecretStr) -> bool:
    """Return True when *x_token* is still accepted by Yandex Passport.

    A ``False`` return signals "rejected by Passport" — a terminal
    credential failure. Transient network or rate-limit errors are re-raised
    so callers can distinguish them from invalid credentials and avoid
    clearing a good token on a temporary outage.

    Args:
        x_token: The token to validate.

    Raises:
        NetworkError: Transient network failure reaching Passport.
        RateLimitedError: Passport returned 429.
    """
    try:
        async with PassportClient.create() as client:
            return bool(await client.validate_x_token(x_token))
    except (NetworkError, RateLimitedError):
        raise
    except YaPassportError:
        return False
