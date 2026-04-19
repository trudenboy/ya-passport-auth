"""High-level ``PassportClient`` facade.

The facade owns an :class:`aiohttp.ClientSession` with a dedicated
cookie jar and wires up every flow, the rate limiter, and the HTTP
client. Callers should use :meth:`create` (async context manager) or
manage the session lifecycle explicitly via ``__aenter__``/``close``.
"""

from __future__ import annotations

import asyncio
import inspect
import time
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Final

import aiohttp

from ya_passport_auth.config import ClientConfig
from ya_passport_auth.credentials import Credentials, SecretStr
from ya_passport_auth.exceptions import (
    DeviceCodeTimeoutError,
    InvalidCredentialsError,
    QRTimeoutError,
    YaPassportError,
)
from ya_passport_auth.flows._token_exchange import (
    exchange_cookies_for_x_token,
    exchange_x_token_for_music_token,
)
from ya_passport_auth.flows.account import AccountInfoFetcher
from ya_passport_auth.flows.cookie_login import CookieLoginFlow
from ya_passport_auth.flows.device_code import DeviceCodeFlow, PollOutcome
from ya_passport_auth.flows.glagol import GlagolDeviceTokenFetcher
from ya_passport_auth.flows.qr import QrLoginFlow, QrSession
from ya_passport_auth.flows.quasar import QuasarCsrfFetcher
from ya_passport_auth.flows.session import PassportSessionRefresher
from ya_passport_auth.http import SafeHttpClient
from ya_passport_auth.logging import get_logger
from ya_passport_auth.models import AccountInfo, DeviceCodeSession, OAuthTokens
from ya_passport_auth.rate_limit import AsyncMinDelayLimiter

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable

__all__ = ["PassportClient"]

_log = get_logger("client")

# RFC 8628 §3.5: on ``slow_down`` the client MUST increase its polling
# interval by at least 5 seconds for this and all subsequent requests.
_SLOW_DOWN_INCREMENT_S: Final = 5.0


class PassportClient:
    """Async Yandex Passport client — the library's primary public API.

    Wraps every authentication and token-exchange flow behind a single
    object with a managed HTTP session.
    """

    __slots__ = (
        "_config",
        "_device",
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
        self._device = DeviceCodeFlow(http=self._http)

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
    # Cookie login
    # ------------------------------------------------------------------ #
    async def login_cookies(self, cookies: str) -> Credentials:
        """Exchange raw browser cookies for :class:`Credentials`.

        *cookies* should be a semicolon-separated ``key=value`` string.
        """
        flow = CookieLoginFlow(http=self._http)
        x_token = await flow.login(cookies)
        return await self._complete_auth_from_x_token(x_token)

    # ------------------------------------------------------------------ #
    # Device flow login
    # ------------------------------------------------------------------ #
    async def start_device_login(
        self,
        device_id: str | None = None,
        device_name: str | None = None,
    ) -> DeviceCodeSession:
        """Request a device code; caller displays ``user_code`` to the user."""
        return await self._device.request_code(device_id, device_name)

    async def poll_device_until_confirmed(
        self,
        session: DeviceCodeSession,
        *,
        poll_interval: float | None = None,
        total_timeout: float | None = None,
        should_cancel: Callable[[], bool] | None = None,
    ) -> Credentials:
        """Poll until the device code is confirmed, then assemble credentials.

        Defaults follow the server-provided ``interval`` and ``expires_in``
        values from :class:`DeviceCodeSession`. Raises
        :class:`DeviceCodeTimeoutError` if the deadline elapses and
        :class:`InvalidCredentialsError` if ``should_cancel`` returns ``True``.
        """
        interval = session.interval if poll_interval is None else poll_interval
        timeout = session.expires_in if total_timeout is None else total_timeout
        if interval <= 0:
            raise ValueError("poll_interval must be positive")
        if timeout <= 0:
            raise ValueError("total_timeout must be positive")

        deadline = time.monotonic() + timeout
        while True:
            if should_cancel is not None and should_cancel():
                raise InvalidCredentialsError("device login cancelled")

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DeviceCodeTimeoutError("device polling timed out")

            result = await self._device.poll_token(session.device_code)
            if isinstance(result, OAuthTokens):
                _log.info("Device code confirmed")
                return await self._complete_auth_from_x_token(
                    result.access_token,
                    refresh_token=result.refresh_token,
                )
            if result is PollOutcome.SLOW_DOWN:
                interval += _SLOW_DOWN_INCREMENT_S
                _log.warning("slow_down received; increasing poll interval to %.1fs", interval)
                remaining = deadline - time.monotonic()
                if interval > remaining:
                    # RFC 8628 §3.5 forbids polling faster than the bumped
                    # interval; if the deadline is too close to honor it,
                    # stop rather than send one final too-fast request.
                    raise DeviceCodeTimeoutError("device polling timed out after slow_down")

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DeviceCodeTimeoutError("device polling timed out")
            await asyncio.sleep(min(interval, remaining))

    async def login_device_code(
        self,
        *,
        on_code: Callable[[DeviceCodeSession], None | Awaitable[None]],
        poll_interval: float | None = None,
        total_timeout: float | None = None,
        should_cancel: Callable[[], bool] | None = None,
        device_id: str | None = None,
        device_name: str | None = None,
    ) -> Credentials:
        """Run the full OAuth Device Flow end-to-end.

        ``on_code`` is invoked once with the :class:`DeviceCodeSession` so the
        caller can display ``session.user_code`` and ``session.verification_url``.
        Both sync callbacks and coroutines are supported.
        """
        session = await self.start_device_login(device_id, device_name)

        result = on_code(session)
        if inspect.isawaitable(result):
            await result

        return await self.poll_device_until_confirmed(
            session,
            poll_interval=poll_interval,
            total_timeout=total_timeout,
            should_cancel=should_cancel,
        )

    async def refresh_credentials(self, credentials: Credentials) -> Credentials:
        """Mint a new x_token from a stored refresh_token.

        Only device-flow credentials carry a refresh_token; QR/cookie-login
        credentials have ``refresh_token=None`` and cannot be refreshed
        without repeating the original login.
        """
        if credentials.refresh_token is None:
            raise InvalidCredentialsError("credentials have no refresh_token")
        tokens = await self._device.refresh(credentials.refresh_token)
        return await self._complete_auth_from_x_token(
            tokens.access_token,
            refresh_token=tokens.refresh_token,
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

        Used when authentication has already established session cookies
        in the client's cookie jar, such as the QR login flow. This does
        not handle the raw-cookie login path used by ``login_cookies()``.
        """
        x_token = await exchange_cookies_for_x_token(self._http, self._session)
        return await self._complete_auth_from_x_token(x_token)

    async def _complete_auth_from_x_token(
        self,
        x_token: SecretStr,
        *,
        refresh_token: SecretStr | None = None,
    ) -> Credentials:
        """Exchange x_token → music_token, fetch account info, assemble creds.

        Shared tail for auth flows that already hold an ``x_token``. QR and
        other session-cookie flows reach this via :meth:`_complete_auth`,
        while raw-cookie login, device-flow, and refresh-based paths may
        call it directly.
        """
        music_token = await exchange_x_token_for_music_token(self._http, x_token)
        return await self._build_credentials(
            x_token,
            music_token,
            refresh_token=refresh_token,
        )

    async def _build_credentials(
        self,
        x_token: SecretStr,
        music_token: SecretStr,
        *,
        refresh_token: SecretStr | None = None,
    ) -> Credentials:
        """Fetch optional account info and assemble :class:`Credentials`."""
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
            refresh_token=refresh_token,
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
