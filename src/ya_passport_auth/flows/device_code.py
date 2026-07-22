"""OAuth Device Flow against ``oauth.yandex.ru``.

The flow is parameterized by OAuth client credentials and an optional scope.
Its defaults preserve the Passport Android behavior used by
:class:`~ya_passport_auth.PassportClient`; callers such as the Yandex Disk
provider can instead supply their own OAuth application and request a
service-specific scope.

The endpoint surfaces OAuth errors with HTTP 400 and a JSON body such
as ``{"error": "authorization_pending", "error_description": "..."}``.
Since :class:`SafeHttpClient` does not raise on 4xx, the parsed body is
returned and we dispatch structurally on ``data.get("error")``.
"""

from __future__ import annotations

import secrets
import string
from enum import Enum
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
from ya_passport_auth.flows._payload import (
    require_int as _require_int,
)
from ya_passport_auth.flows._payload import (
    require_str as _require_str,
)
from ya_passport_auth.flows._polling import (
    Confirmed,
    Pending,
    PollResult,
    SlowDown,
    drive_login,
)
from ya_passport_auth.logging import get_logger
from ya_passport_auth.models import DeviceCodeSession, OAuthTokens

if TYPE_CHECKING:
    from collections.abc import Callable

    from ya_passport_auth.http import SafeHttpClient

__all__ = ["DeviceCodeFlow", "PollOutcome"]


class PollOutcome(Enum):
    """Non-terminal outcomes of a single device-code poll.

    ``PENDING`` means the user has not yet confirmed the code; the caller
    should keep polling at the current interval. ``SLOW_DOWN`` (RFC 8628
    §3.5) means the client is polling too fast and must increase its
    interval by at least five seconds for this and all subsequent requests.
    """

    PENDING = "authorization_pending"
    SLOW_DOWN = "slow_down"


_log = get_logger("device_code")

_DEFAULT_DEVICE_NAME: Final = "ya-passport-auth"
_DEVICE_ID_ALPHABET: Final = string.ascii_letters + string.digits
_DEVICE_ID_LENGTH: Final = 10
_SLOW_DOWN_INCREMENT_S: Final = 5.0


def _generate_device_id() -> str:
    """Return a random 10-character alphanumeric device identifier."""
    return "".join(secrets.choice(_DEVICE_ID_ALPHABET) for _ in range(_DEVICE_ID_LENGTH))


class DeviceCodeFlow:
    """Low-level OAuth Device Flow steps.

    :class:`~ya_passport_auth.PassportClient` and
    :class:`~ya_passport_auth.OAuthDeviceClient` compose these steps into a
    full flow with polling, timeout, and cancellation.
    """

    __slots__ = ("_client_id", "_client_secret", "_http", "_scope")

    def __init__(
        self,
        *,
        http: SafeHttpClient,
        client_id: str = PASSPORT_CLIENT_ID,
        client_secret: str | SecretStr = PASSPORT_CLIENT_SECRET,
        scope: str | None = None,
    ) -> None:
        if not client_id:
            raise ValueError("client_id must not be empty")
        if isinstance(client_secret, str):
            client_secret = SecretStr(client_secret)
        if scope is not None and not scope.strip():
            raise ValueError("scope must be None or a non-empty string")
        self._http = http
        self._client_id = client_id
        self._client_secret = client_secret
        self._scope = scope

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
        request_data: dict[str, object] = {
            "client_id": self._client_id,
            "device_id": device_id or _generate_device_id(),
            "device_name": device_name or _DEFAULT_DEVICE_NAME,
        }
        if self._scope is not None:
            request_data["scope"] = self._scope
        data = await self._http.post_json(DEVICE_CODE_URL, data=request_data)

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

        _log.info(
            "Device code issued, expires_in=%s interval=%s",
            expires_in,
            interval,
        )
        return DeviceCodeSession(
            device_code=SecretStr(device_code),
            user_code=user_code,
            verification_url=verification_url,
            expires_in=expires_in,
            interval=interval,
        )

    async def poll_token(self, device_code: SecretStr) -> OAuthTokens | PollOutcome:
        """Poll the token endpoint once.

        Returns :class:`OAuthTokens` when the user has confirmed, or a
        :class:`PollOutcome` member describing the non-terminal state:
        ``PENDING`` for ``authorization_pending`` or ``SLOW_DOWN`` when
        RFC 8628 §3.5 asks the caller to back off.

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
                "client_id": self._client_id,
                "client_secret": self._client_secret.get_secret(),
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
                "client_id": self._client_id,
                "client_secret": self._client_secret.get_secret(),
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

    async def poll_until_confirmed(
        self,
        session: DeviceCodeSession,
        *,
        poll_interval: float | None = None,
        total_timeout: float | None = None,
        should_cancel: Callable[[], bool] | None = None,
    ) -> OAuthTokens:
        """Poll until the user confirms *session* and return OAuth tokens."""
        interval = session.interval if poll_interval is None else poll_interval
        timeout = session.expires_in if total_timeout is None else total_timeout
        if interval <= 0:
            raise ValueError("poll_interval must be positive")
        if timeout <= 0:
            raise ValueError("total_timeout must be positive")

        async def _poll() -> PollResult[OAuthTokens]:
            result = await self.poll_token(session.device_code)
            if isinstance(result, OAuthTokens):
                return Confirmed(result)
            if result is PollOutcome.SLOW_DOWN:
                _log.warning(
                    "slow_down received; increasing poll interval by %.1fs",
                    _SLOW_DOWN_INCREMENT_S,
                )
                return SlowDown(_SLOW_DOWN_INCREMENT_S)
            return Pending()

        return await drive_login(
            poll_one=_poll,
            interval=interval,
            total_timeout=timeout,
            timeout_exc=DeviceCodeTimeoutError,
            timeout_message="device polling timed out",
            should_cancel=should_cancel,
        )


def _parse_token_response(data: dict[str, object]) -> OAuthTokens | PollOutcome:
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
        return PollOutcome.PENDING
    if error == "slow_down":
        return PollOutcome.SLOW_DOWN
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
