"""High-level ``PassportClient`` facade.

The facade owns an :class:`aiohttp.ClientSession` with a dedicated
cookie jar and wires up every flow, the rate limiter, and the HTTP
client. Callers should use :meth:`create` (async context manager) or
manage the session lifecycle explicitly via ``__aenter__``/``close``.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import aiohttp

from ya_passport_auth.config import ClientConfig
from ya_passport_auth.credentials import Credentials, SecretStr
from ya_passport_auth.exceptions import QRTimeoutError, YaPassportError
from ya_passport_auth.flows.account import AccountInfoFetcher
from ya_passport_auth.flows.glagol import GlagolDeviceTokenFetcher
from ya_passport_auth.flows.qr import QrLoginFlow, QrSession
from ya_passport_auth.flows.quasar import QuasarCsrfFetcher
from ya_passport_auth.flows.session import PassportSessionRefresher
from ya_passport_auth.http import SafeHttpClient
from ya_passport_auth.logging import get_logger
from ya_passport_auth.models import AccountInfo
from ya_passport_auth.rate_limit import AsyncMinDelayLimiter

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

__all__ = ["PassportClient"]

_log = get_logger("client")


class PassportClient:
    """Async Yandex Passport client — the library's primary public API.

    Wraps every authentication and token-exchange flow behind a single
    object with a managed HTTP session.
    """

    __slots__ = (
        "_config",
        "_http",
        "_owns_session",
        "_qr",
        "_session",
    )

    def __init__(
        self,
        *,
        session: aiohttp.ClientSession | None = None,
        config: ClientConfig | None = None,
    ) -> None:
        self._config = config or ClientConfig()
        self._owns_session = session is None
        if session is None:
            jar = aiohttp.CookieJar()
            self._session = aiohttp.ClientSession(
                cookie_jar=jar,
                headers={"User-Agent": self._config.user_agent},
                timeout=aiohttp.ClientTimeout(
                    total=self._config.total_timeout_seconds,
                    connect=self._config.connect_timeout_seconds,
                ),
            )
        else:
            self._session = session

        limiter = AsyncMinDelayLimiter(
            self._config.min_request_interval_seconds,
        )
        self._http = SafeHttpClient(
            session=self._session,
            config=self._config,
            limiter=limiter,
        )
        self._qr = QrLoginFlow(http=self._http, session=self._session)

    @classmethod
    @asynccontextmanager
    async def create(
        cls,
        config: ClientConfig | None = None,
    ) -> AsyncIterator[PassportClient]:
        """Create a ``PassportClient`` that owns its own session."""
        client = cls(config=config)
        try:
            yield client
        finally:
            await client.close()

    # ------------------------------------------------------------------ #
    # QR login
    # ------------------------------------------------------------------ #
    async def start_qr_login(self) -> QrSession:
        """Begin a QR login flow; return a session handle with the QR URL."""
        return await self._qr.get_qr()

    async def poll_qr_until_confirmed(
        self,
        qr: QrSession,
        *,
        poll_interval: float | None = None,
        total_timeout: float | None = None,
    ) -> Credentials:
        """Poll until the QR code is confirmed, then exchange tokens.

        Raises :class:`QRTimeoutError` if ``total_timeout`` expires.
        """
        interval = self._config.qr_poll_interval_seconds if poll_interval is None else poll_interval
        timeout = (
            self._config.qr_poll_total_timeout_seconds if total_timeout is None else total_timeout
        )
        if interval <= 0:
            raise ValueError("poll_interval must be positive")
        if timeout <= 0:
            raise ValueError("total_timeout must be positive")

        elapsed = 0.0
        while elapsed < timeout:
            await asyncio.sleep(interval)
            elapsed += interval

            if await self._qr.check_status(qr):
                _log.info("QR confirmed after %.0fs", elapsed)
                return await self.complete_qr_login(qr)

        raise QRTimeoutError("QR polling timed out")

    async def complete_qr_login(self, qr: QrSession) -> Credentials:
        """Exchange a confirmed QR session for full credentials.

        Call this after ``check_status`` returns ``True``, or let
        ``poll_qr_until_confirmed`` call it automatically.
        """
        del qr  # cookies are in the session jar
        x_token = await self._qr.get_x_token()
        music_token = await self._qr.get_music_token(x_token)

        try:
            info = await self.fetch_account_info(x_token)
            uid = info.uid
            login = info.display_login
        except (YaPassportError, aiohttp.ClientError, TimeoutError):
            _log.debug("account info fetch failed; continuing without metadata")
            uid = None
            login = None

        return Credentials(
            x_token=x_token,
            music_token=music_token,
            uid=uid,
            display_login=login,
        )

    # ------------------------------------------------------------------ #
    # Token ops
    # ------------------------------------------------------------------ #
    async def refresh_music_token(self, x_token: SecretStr) -> SecretStr:
        """Exchange an ``x_token`` for a fresh music-scoped OAuth token."""
        return await self._qr.get_music_token(x_token)

    async def refresh_passport_cookies(self, x_token: SecretStr) -> None:
        """Refresh Passport session cookies from an ``x_token``."""
        refresher = PassportSessionRefresher(
            http=self._http,
            session=self._session,
        )
        await refresher.refresh(x_token)

    async def get_quasar_csrf_token(self) -> SecretStr:
        """Fetch a Quasar CSRF token (requires active Passport cookies)."""
        fetcher = QuasarCsrfFetcher(http=self._http)
        return await fetcher.fetch()

    async def get_glagol_device_token(
        self,
        music_token: SecretStr,
        *,
        device_id: str,
        platform: str,
    ) -> SecretStr:
        """Fetch a Glagol local-network device token."""
        fetcher = GlagolDeviceTokenFetcher(http=self._http)
        return await fetcher.fetch(
            music_token=music_token,
            device_id=device_id,
            platform=platform,
        )

    async def fetch_account_info(self, x_token: SecretStr) -> AccountInfo:
        """Fetch account metadata from ``short_info``."""
        fetcher = AccountInfoFetcher(http=self._http)
        return await fetcher.fetch(x_token)

    async def validate_x_token(self, x_token: SecretStr) -> bool:
        """Return ``True`` if the ``x_token`` is accepted by ``short_info``."""
        fetcher = AccountInfoFetcher(http=self._http)
        return await fetcher.validate(x_token)

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    async def close(self) -> None:
        """Close the internal session if owned."""
        if self._owns_session:
            await self._session.close()

    async def __aenter__(self) -> PassportClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()
