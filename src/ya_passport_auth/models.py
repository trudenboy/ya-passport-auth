"""Data models used across the library."""

from __future__ import annotations

from dataclasses import dataclass

from ya_passport_auth.credentials import SecretStr

__all__ = ["AccountInfo", "DeviceCodeSession", "OAuthTokens"]


@dataclass(frozen=True, slots=True)
class AccountInfo:
    """Non-secret account metadata from the ``short_info`` endpoint."""

    uid: int
    display_login: str | None = None
    display_name: str | None = None
    public_id: str | None = None


@dataclass(frozen=True, slots=True, repr=False)
class DeviceCodeSession:
    """In-progress OAuth Device Flow handle returned by ``start_device_login``.

    ``user_code`` is the short string the caller shows to the user.
    ``device_code`` is wrapped in :class:`SecretStr` because a third party
    holding it can race the user to the token endpoint during the
    confirmation window.
    """

    device_code: SecretStr
    user_code: str
    verification_url: str
    expires_in: int
    interval: int

    def __repr__(self) -> str:
        # Surface only non-secret fields useful for debugging; the
        # ``device_code`` is a SecretStr and would redact itself, but we
        # omit ``user_code`` to keep log output generic.
        return (
            f"DeviceCodeSession(verification_url={self.verification_url!r}, "
            f"expires_in={self.expires_in})"
        )


@dataclass(frozen=True, slots=True, repr=False)
class OAuthTokens:
    """OAuth token pair returned by the Device Flow token endpoint."""

    access_token: SecretStr
    refresh_token: SecretStr
    expires_in: int

    def __repr__(self) -> str:
        return f"OAuthTokens(access_token='***', refresh_token='***', expires_in={self.expires_in})"
