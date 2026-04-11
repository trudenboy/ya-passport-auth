"""Exception hierarchy for ya-passport-auth.

All errors raised by the library derive from :class:`YaPassportError` so a
caller can catch everything with a single ``except`` clause. Two subtrees
split the problem space:

* :class:`NetworkError` — transport/host issues (connection, TLS,
  unexpected destination). Retryable in principle.
* :class:`AuthFailedError` — the remote side spoke HTTP successfully
  but refused to authenticate, or a higher-level auth invariant was
  violated. Not generally retryable.

Every exception carries ``status_code`` and ``endpoint`` attributes to
give callers structured context without forcing them to regex-match
``str(exc)``. ``endpoint`` is normalized to scheme+host+path — query
strings and fragments are dropped because they can carry secrets.

Constructors refuse to accept :class:`SecretStr` or :class:`Credentials`
directly. This protects threat-model item T1 (token leak via
tracebacks): if the library never stores a token-like object inside an
exception, it cannot be re-rendered anywhere downstream.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from ya_passport_auth.credentials import Credentials, SecretStr

__all__ = [
    "AccountNotFoundError",
    "AuthFailedError",
    "CaptchaRequiredError",
    "CsrfExtractionError",
    "InvalidCredentialsError",
    "NetworkError",
    "PasswordError",
    "QRPendingError",
    "QRTimeoutError",
    "RateLimitedError",
    "UnexpectedHostError",
    "YaPassportError",
]


def _sanitize_endpoint(endpoint: str | None) -> str | None:
    if endpoint is None:
        return None
    parts = urlsplit(endpoint)
    # Drop query, fragment, and userinfo; keep scheme/host/path only.
    host = parts.hostname or ""
    netloc = f"{host}:{parts.port}" if parts.port else host
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def _reject_secret_like(message: object) -> None:
    if isinstance(message, SecretStr):
        raise TypeError(
            "YaPassportError messages must not wrap a SecretStr — pass a plain description instead",
        )
    if isinstance(message, Credentials):
        raise TypeError(
            "YaPassportError messages must not wrap a Credentials — "
            "pass a plain description instead",
        )


class YaPassportError(Exception):
    """Root of the ya-passport-auth exception hierarchy."""

    default_status_code: int | None = None

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        endpoint: str | None = None,
    ) -> None:
        _reject_secret_like(message)
        super().__init__(message)
        self.status_code: int | None = (
            status_code if status_code is not None else self.default_status_code
        )
        self.endpoint: str | None = _sanitize_endpoint(endpoint)


class NetworkError(YaPassportError):
    """Transport or host-layer failure."""


class UnexpectedHostError(NetworkError):
    """Response came from a host outside the allow-list."""


class AuthFailedError(YaPassportError):
    """The authentication workflow failed at the application level."""


class InvalidCredentialsError(AuthFailedError):
    """Token or QR session is rejected by the server."""


class CsrfExtractionError(AuthFailedError):
    """CSRF token could not be extracted from a Passport HTML page."""


class RateLimitedError(AuthFailedError):
    """Server returned HTTP 429 — caller must back off."""

    default_status_code = 429


class QRPendingError(AuthFailedError):
    """QR code has not been confirmed yet — keep polling."""


class QRTimeoutError(AuthFailedError):
    """QR polling loop expired without confirmation."""


class AccountNotFoundError(AuthFailedError):
    """The login/username does not exist (account can only be registered)."""


class PasswordError(AuthFailedError):
    """Password was rejected (wrong password, expired OTP, etc.)."""


class CaptchaRequiredError(AuthFailedError):
    """Server requires CAPTCHA before proceeding."""
