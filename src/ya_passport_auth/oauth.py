"""Public client for Yandex's official OAuth Device Authorization Flow."""

from __future__ import annotations

import inspect
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import aiohttp

from ya_passport_auth.config import ClientConfig
from ya_passport_auth.credentials import SecretStr
from ya_passport_auth.flows.device_code import DeviceCodeFlow
from ya_passport_auth.http import SafeHttpClient
from ya_passport_auth.models import DeviceCodeSession, OAuthTokens
from ya_passport_auth.rate_limit import AsyncMinDelayLimiter

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable

__all__ = ["OAuthDeviceClient"]


class OAuthDeviceClient:
    """Run Device Flow for a caller-owned Yandex OAuth application.

    Unlike :class:`~ya_passport_auth.PassportClient`, this client returns the
    service-scoped OAuth token pair unchanged. It does not treat the access
    token as a Passport ``x_token`` or exchange it for a Yandex Music token.
    """

    __slots__ = ("_device", "_owns_session", "_session")

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str | SecretStr,
        scope: str | None = None,
        session: aiohttp.ClientSession | None = None,
        config: ClientConfig | None = None,
    ) -> None:
        """Initialize a client with the caller's OAuth application credentials."""
        oauth_config = config or ClientConfig()
        self._owns_session = session is None
        if session is None:
            self._session = aiohttp.ClientSession(
                cookie_jar=aiohttp.CookieJar(),
                headers={"User-Agent": oauth_config.user_agent},
                timeout=aiohttp.ClientTimeout(
                    total=oauth_config.total_timeout_seconds,
                    connect=oauth_config.connect_timeout_seconds,
                ),
            )
        else:
            self._session = session

        http = SafeHttpClient(
            session=self._session,
            config=oauth_config,
            limiter=AsyncMinDelayLimiter(oauth_config.min_request_interval_seconds),
        )
        self._device = DeviceCodeFlow(
            http=http,
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
        )

    @classmethod
    @asynccontextmanager
    async def create(
        cls,
        *,
        client_id: str,
        client_secret: str | SecretStr,
        scope: str | None = None,
        session: aiohttp.ClientSession | None = None,
        config: ClientConfig | None = None,
    ) -> AsyncIterator[OAuthDeviceClient]:
        """Create a client and close only a session created by the client."""
        client = cls(
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
            session=session,
            config=config,
        )
        try:
            yield client
        finally:
            await client.close()

    async def start_device_login(
        self,
        device_id: str | None = None,
        device_name: str | None = None,
    ) -> DeviceCodeSession:
        """Request a device code; the caller displays it to the user."""
        return await self._device.request_code(device_id, device_name)

    async def poll_device_until_confirmed(
        self,
        session: DeviceCodeSession,
        *,
        poll_interval: float | None = None,
        total_timeout: float | None = None,
        should_cancel: Callable[[], bool] | None = None,
    ) -> OAuthTokens:
        """Poll until the user confirms *session* and return OAuth tokens."""
        return await self._device.poll_until_confirmed(
            session,
            poll_interval=poll_interval,
            total_timeout=total_timeout,
            should_cancel=should_cancel,
        )

    async def login_device_code(
        self,
        *,
        on_code: Callable[[DeviceCodeSession], None | Awaitable[None]],
        poll_interval: float | None = None,
        total_timeout: float | None = None,
        should_cancel: Callable[[], bool] | None = None,
        device_id: str | None = None,
        device_name: str | None = None,
    ) -> OAuthTokens:
        """Run the caller-owned OAuth Device Flow end-to-end."""
        session = await self.start_device_login(device_id, device_name)
        callback_result = on_code(session)
        if inspect.isawaitable(callback_result):
            await callback_result
        return await self.poll_device_until_confirmed(
            session,
            poll_interval=poll_interval,
            total_timeout=total_timeout,
            should_cancel=should_cancel,
        )

    async def refresh(self, refresh_token: str | SecretStr) -> OAuthTokens:
        """Exchange a refresh token for a fresh access/refresh token pair."""
        if isinstance(refresh_token, str):
            refresh_token = SecretStr(refresh_token)
        return await self._device.refresh(refresh_token)

    async def close(self) -> None:
        """Close the internally-owned HTTP session, if any."""
        if self._owns_session:
            await self._session.close()

    async def __aenter__(self) -> OAuthDeviceClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()
