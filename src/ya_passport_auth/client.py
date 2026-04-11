"""High-level ``PassportClient`` facade.

The facade owns an :class:`aiohttp.ClientSession` with a dedicated
cookie jar and wires up every flow, the rate limiter, and the HTTP
client. Callers should use :meth:`create` (async context manager) or
manage the session lifecycle explicitly via ``__aenter__``/``close``.
"""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import aiohttp

from ya_passport_auth.config import ClientConfig
from ya_passport_auth.credentials import Credentials, SecretStr
from ya_passport_auth.exceptions import AuthFailedError, QRTimeoutError, YaPassportError
from ya_passport_auth.flows._token_exchange import (
    exchange_cookies_for_x_token,
    exchange_x_token_for_music_token,
)
from ya_passport_auth.flows.account import AccountInfoFetcher
from ya_passport_auth.flows.cookie_login import CookieLoginFlow
from ya_passport_auth.flows.glagol import GlagolDeviceTokenFetcher
from ya_passport_auth.flows.password import PasswordLoginFlow
from ya_passport_auth.flows.qr import QrLoginFlow, QrSession
from ya_passport_auth.flows.quasar import QuasarCsrfFetcher
from ya_passport_auth.flows.session import PassportSessionRefresher
from ya_passport_auth.http import SafeHttpClient
from ya_passport_auth.logging import get_logger
from ya_passport_auth.models import AccountInfo, AuthSession, CaptchaChallenge
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
        """Create a PassportClient.

        When *session* is ``None`` (the default), an internal session
        is created with TLS verification enabled and a dedicated cookie
        jar.  When an external session is supplied the caller is
        responsible for ensuring TLS verification is not disabled —
        the library cannot enforce this on externally-created sessions.
        Prefer :meth:`create` for the safest defaults.
        """
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

        deadline = time.monotonic() + timeout
        while True:
            if await self._qr.check_status(qr):
                _log.info("QR confirmed")
                return await self.complete_qr_login(qr)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            await asyncio.sleep(min(interval, remaining))

        raise QRTimeoutError("QR polling timed out")

    async def complete_qr_login(self, qr: QrSession) -> Credentials:
        """Exchange a confirmed QR session for full credentials.

        Call this after ``check_status`` returns ``True``, or let
        ``poll_qr_until_confirmed`` call it automatically.
        """
        del qr  # cookies are in the session jar
        return await self._complete_auth()

    # ------------------------------------------------------------------ #
    # Password / SMS / magic-link / captcha login
    # ------------------------------------------------------------------ #
    async def start_password_auth(self, username: str) -> AuthSession:
        """Begin a multi-step password login; return a session handle.

        The returned :class:`AuthSession` carries ``auth_methods`` — a
        tuple of the methods Yandex will accept for this account (e.g.
        ``("password", "magic_x_token", "sms")``).
        """
        flow = PasswordLoginFlow(http=self._http)
        return await flow.start_auth(username)

    async def login_password(
        self,
        auth: AuthSession,
        password: str,
    ) -> Credentials:
        """Submit a password and exchange tokens for :class:`Credentials`.

        Raises :class:`PasswordError` on wrong password,
        :class:`CaptchaRequiredError` if CAPTCHA is needed first.
        """
        flow = PasswordLoginFlow(http=self._http)
        await flow.submit_password(auth, password)
        return await self._complete_auth()

    async def request_sms(self, auth: AuthSession) -> None:
        """Request an SMS code be sent to the account's phone number."""
        flow = PasswordLoginFlow(http=self._http)
        await flow.request_sms(auth)

    async def login_sms(self, auth: AuthSession, code: str) -> Credentials:
        """Verify an SMS code and exchange tokens for :class:`Credentials`."""
        flow = PasswordLoginFlow(http=self._http)
        await flow.submit_sms(auth, code)
        return await self._complete_auth()

    async def request_magic_link(self, auth: AuthSession) -> None:
        """Send a magic-link confirmation email to the account."""
        flow = PasswordLoginFlow(http=self._http)
        await flow.request_magic_link(auth)

    async def check_magic_link(self, auth: AuthSession) -> bool:
        """Check magic link status. Returns ``True`` when confirmed."""
        flow = PasswordLoginFlow(http=self._http)
        return await flow.check_magic_link(auth)

    async def poll_magic_link(
        self,
        auth: AuthSession,
        *,
        poll_interval: float | None = None,
        total_timeout: float | None = None,
    ) -> Credentials:
        """Poll until the magic link is confirmed, then exchange tokens.

        Raises :class:`AuthFailedError` if ``total_timeout`` expires.
        """
        interval = self._config.qr_poll_interval_seconds if poll_interval is None else poll_interval
        timeout = (
            self._config.qr_poll_total_timeout_seconds if total_timeout is None else total_timeout
        )
        if interval <= 0:
            raise ValueError("poll_interval must be positive")
        if timeout <= 0:
            raise ValueError("total_timeout must be positive")

        deadline = time.monotonic() + timeout
        flow = PasswordLoginFlow(http=self._http)
        while True:
            if await flow.check_magic_link(auth):
                _log.info("magic link confirmed")
                return await self._complete_auth()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            await asyncio.sleep(min(interval, remaining))

        raise AuthFailedError("magic link polling timed out")

    async def get_captcha(self, auth: AuthSession) -> CaptchaChallenge:
        """Fetch a CAPTCHA challenge that must be solved before login."""
        flow = PasswordLoginFlow(http=self._http)
        return await flow.get_captcha(auth)

    async def solve_captcha(
        self,
        auth: AuthSession,
        challenge: CaptchaChallenge,
        answer: str,
    ) -> bool:
        """Submit a CAPTCHA answer. Returns ``True`` if accepted."""
        flow = PasswordLoginFlow(http=self._http)
        return await flow.submit_captcha(auth, challenge, answer)

    # ------------------------------------------------------------------ #
    # Cookie login
    # ------------------------------------------------------------------ #
    async def login_cookies(self, cookies: str) -> Credentials:
        """Exchange raw browser cookies for :class:`Credentials`.

        *cookies* should be a semicolon-separated ``key=value`` string.
        """
        flow = CookieLoginFlow(http=self._http)
        x_token = await flow.login(cookies)
        music_token = await exchange_x_token_for_music_token(self._http, x_token)

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
        return await exchange_x_token_for_music_token(self._http, x_token)

    async def refresh_passport_cookies(self, x_token: SecretStr) -> None:
        """Refresh Passport session cookies from an ``x_token``."""
        refresher = PassportSessionRefresher(http=self._http)
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
    # Shared auth completion
    # ------------------------------------------------------------------ #
    async def _complete_auth(self) -> Credentials:
        """Exchange session cookies → x_token → music_token → Credentials.

        Shared by QR, password, SMS, and magic-link flows. Expects
        session cookies to already be present in the cookie jar.
        """
        x_token = await exchange_cookies_for_x_token(self._http, self._session)
        music_token = await exchange_x_token_for_music_token(self._http, x_token)

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
