"""OAuth Device Flow against ``oauth.yandex.ru``.

Yielded tokens are equivalent to an ``x_token`` — the request uses the
Passport Android ``client_id``/``client_secret`` pair, so the same token
can be exchanged for a music token, passed to ``short_info``, and used
to mint session cookies just like a QR/cookie-login result.

The endpoint surfaces OAuth errors with HTTP 400 and a JSON body such
as ``{"error": "authorization_pending", "error_description": "..."}``.
Since :class:`SafeHttpClient` does not raise on 4xx, the parsed body is
returned and we dispatch structurally on ``data.get("error")``.
"""

from __future__ import annotations

import secrets
import string
from typing import TYPE_CHECKING, Final

from ya_passport_auth.constants import (
    DEVICE_CODE_URL,
    OAUTH_TOKEN_URL,
    PASSPORT_CLIENT_ID,
    PASSPORT_CLIENT_SECRET,
)
from ya_passport_auth.credentials import SecretStr
from ya_passport_auth.exceptions import (
    AuthFailedError,
    DeviceCodeTimeoutError,
    InvalidCredentialsError,
)
from ya_passport_auth.logging import get_logger
from ya_passport_auth.models import DeviceCodeSession, OAuthTokens

if TYPE_CHECKING:
    from ya_passport_auth.http import SafeHttpClient

__all__ = ["DeviceCodeFlow"]

_log = get_logger("device_code")

_DEFAULT_DEVICE_NAME: Final = "ya-passport-auth"
_DEVICE_ID_ALPHABET: Final = string.ascii_letters + string.digits
_DEVICE_ID_LENGTH: Final = 10


def _generate_device_id() -> str:
    """Return a random 10-character alphanumeric device identifier."""
    return "".join(secrets.choice(_DEVICE_ID_ALPHABET) for _ in range(_DEVICE_ID_LENGTH))


def _require_str(data: dict[str, object], key: str, endpoint: str) -> str:
    raw = data.get(key)
    if not isinstance(raw, str) or not raw:
        raise AuthFailedError(
            f"device/code response missing {key!r}",
            endpoint=endpoint,
        )
    return raw


def _require_int(data: dict[str, object], key: str, endpoint: str) -> int:
    raw = data.get(key)
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise AuthFailedError(
            f"device/code response missing or non-integer {key!r}",
            endpoint=endpoint,
        )
    return raw


class DeviceCodeFlow:
    """Low-level OAuth Device Flow steps.

    The high-level :class:`~ya_passport_auth.PassportClient` composes these
    into a full flow with polling, timeout, and cancellation.
    """

    __slots__ = ("_http",)

    def __init__(self, *, http: SafeHttpClient) -> None:
        self._http = http

    async def request_code(
        self,
        device_id: str | None = None,
        device_name: str | None = None,
    ) -> DeviceCodeSession:
        """Request a device code for OAuth Device Flow.

        Args:
            device_id: Caller-provided device identifier. When ``None``
                a random 10-character alphanumeric string is generated.
            device_name: Human-readable device name shown to the user on
                the confirmation page. Defaults to ``"ya-passport-auth"``.

        Raises:
            AuthFailedError: If the server response is missing an expected
                field or contains an OAuth ``error`` value.
        """
        data = await self._http.post_json(
            DEVICE_CODE_URL,
            data={
                "client_id": PASSPORT_CLIENT_ID,
                "device_id": device_id or _generate_device_id(),
                "device_name": device_name or _DEFAULT_DEVICE_NAME,
            },
        )

        error = data.get("error")
        if isinstance(error, str):
            raise AuthFailedError(
                f"device/code error: {error}",
                endpoint=DEVICE_CODE_URL,
            )

        device_code = _require_str(data, "device_code", DEVICE_CODE_URL)
        user_code = _require_str(data, "user_code", DEVICE_CODE_URL)
        verification_url = _require_str(data, "verification_url", DEVICE_CODE_URL)
        expires_in = _require_int(data, "expires_in", DEVICE_CODE_URL)
        interval = _require_int(data, "interval", DEVICE_CODE_URL)

        _log.info("Device code issued, user_code=%s", user_code)
        return DeviceCodeSession(
            device_code=SecretStr(device_code),
            user_code=user_code,
            verification_url=verification_url,
            expires_in=expires_in,
            interval=interval,
        )

    async def poll_token(self, device_code: SecretStr) -> OAuthTokens | None:
        """Poll the token endpoint once.

        Returns :class:`OAuthTokens` when the user has confirmed, or
        ``None`` while the request is still ``authorization_pending``.

        Raises:
            DeviceCodeTimeoutError: Server reported ``expired_token``.
            InvalidCredentialsError: User denied the login.
            AuthFailedError: Any other OAuth error or an unexpected payload.
        """
        data = await self._http.post_json(
            OAUTH_TOKEN_URL,
            data={
                "grant_type": "device_code",
                "code": device_code.get_secret(),
                "client_id": PASSPORT_CLIENT_ID,
                "client_secret": PASSPORT_CLIENT_SECRET,
            },
        )
        return _parse_token_response(data)

    async def refresh(self, refresh_token: SecretStr) -> OAuthTokens:
        """Exchange a refresh token for a new access/refresh token pair.

        Raises:
            InvalidCredentialsError: Server rejected the refresh_token
                (``invalid_grant``).
            AuthFailedError: Any other OAuth error or an unexpected payload.
        """
        data = await self._http.post_json(
            OAUTH_TOKEN_URL,
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token.get_secret(),
                "client_id": PASSPORT_CLIENT_ID,
                "client_secret": PASSPORT_CLIENT_SECRET,
            },
        )

        error = data.get("error")
        if isinstance(error, str):
            if error == "invalid_grant":
                raise InvalidCredentialsError(
                    "refresh_token rejected",
                    endpoint=OAUTH_TOKEN_URL,
                )
            raise AuthFailedError(
                f"refresh_token error: {error}",
                endpoint=OAUTH_TOKEN_URL,
            )

        tokens = _build_tokens(data)
        if tokens is None:
            raise AuthFailedError(
                "unexpected refresh_token response",
                endpoint=OAUTH_TOKEN_URL,
            )
        return tokens


def _parse_token_response(data: dict[str, object]) -> OAuthTokens | None:
    """Dispatch a parsed ``/token`` response for the device_code grant."""
    if "access_token" in data:
        tokens = _build_tokens(data)
        if tokens is None:
            raise AuthFailedError(
                "unexpected token response",
                endpoint=OAUTH_TOKEN_URL,
            )
        return tokens

    error = data.get("error")
    if not isinstance(error, str):
        raise AuthFailedError(
            "unexpected token response",
            endpoint=OAUTH_TOKEN_URL,
        )

    if error == "authorization_pending":
        return None
    if error == "expired_token":
        raise DeviceCodeTimeoutError(
            "device code expired",
            endpoint=OAUTH_TOKEN_URL,
        )
    if error == "access_denied":
        raise InvalidCredentialsError(
            "user denied device login",
            endpoint=OAUTH_TOKEN_URL,
        )
    raise AuthFailedError(
        f"device token error: {error}",
        endpoint=OAUTH_TOKEN_URL,
    )


def _build_tokens(data: dict[str, object]) -> OAuthTokens | None:
    access = data.get("access_token")
    refresh = data.get("refresh_token")
    expires_in = data.get("expires_in")
    if (
        not isinstance(access, str)
        or not access
        or not isinstance(refresh, str)
        or not refresh
        or isinstance(expires_in, bool)
        or not isinstance(expires_in, int)
    ):
        return None
    return OAuthTokens(
        access_token=SecretStr(access),
        refresh_token=SecretStr(refresh),
        expires_in=expires_in,
    )
