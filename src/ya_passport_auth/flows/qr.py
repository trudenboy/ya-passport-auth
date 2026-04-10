"""QR login flow — CSRF extraction, session creation, polling, token exchange.

This module implements the core mobile Passport QR flow:

1. Fetch the ``/am`` page → extract CSRF token from HTML.
2. POST ``/registration-validations/auth/password/submit`` → get ``track_id``.
3. Build a QR URL from ``track_id``; caller displays it.
4. Poll ``/auth/new/magic/status/`` until ``status == "ok"``.
5. Exchange session cookies for ``x_token``.
6. Exchange ``x_token`` for ``music_token``.

All network I/O goes through :class:`SafeHttpClient`, so host pinning,
size caps, rate limiting, and error wrapping are automatic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from yarl import URL

from ya_passport_auth.constants import (
    CSRF_PATTERNS,
    MUSIC_CLIENT_ID,
    MUSIC_CLIENT_SECRET,
    MUSIC_TOKEN_URL,
    PASSPORT_API_URL,
    PASSPORT_CLIENT_ID,
    PASSPORT_CLIENT_SECRET,
    PASSPORT_URL,
)
from ya_passport_auth.credentials import SecretStr
from ya_passport_auth.exceptions import (
    AuthFailedError,
    CsrfExtractionError,
    InvalidCredentialsError,
)
from ya_passport_auth.logging import get_logger

if TYPE_CHECKING:
    import aiohttp

    from ya_passport_auth.http import SafeHttpClient

__all__ = ["QrLoginFlow", "QrSession"]

_log = get_logger("qr")

_AM_URL = f"{PASSPORT_URL}/am?app_platform=android"
_SUBMIT_URL = f"{PASSPORT_URL}/registration-validations/auth/password/submit"
_STATUS_URL = f"{PASSPORT_URL}/auth/new/magic/status/"
_TOKEN_URL = f"{PASSPORT_API_URL}/1/bundle/oauth/token_by_sessionid"


@dataclass(frozen=True, slots=True)
class QrSession:
    """Opaque handle for an in-progress QR login.

    Callers receive this from :meth:`QrLoginFlow.get_qr` and pass it
    back into :meth:`QrLoginFlow.check_status`. ``qr_url`` is the URL
    to render as a QR code for the user to scan.
    """

    track_id: str
    csrf_token: str
    qr_url: str


def _extract_csrf(html: str) -> str:
    """Try every CSRF pattern against the page. Return the first match."""
    for pattern in CSRF_PATTERNS:
        m = pattern.search(html)
        if m and m.group(1):
            return m.group(1)
    raise CsrfExtractionError(
        "CSRF token not found in Passport HTML",
        endpoint=_AM_URL,
    )


class QrLoginFlow:
    """Low-level QR login steps.

    Each method maps to one HTTP round-trip. The higher-level
    :class:`PassportClient` composes these into a full flow with
    polling and timeout logic.
    """

    __slots__ = ("_http", "_session")

    def __init__(
        self,
        *,
        http: SafeHttpClient,
        session: aiohttp.ClientSession,
    ) -> None:
        self._http = http
        self._session = session

    async def get_qr(self) -> QrSession:
        """Fetch CSRF → create QR auth session → return handle."""
        html = await self._http.get_text(_AM_URL)
        csrf_token = _extract_csrf(html)

        data = await self._http.post_json(
            _SUBMIT_URL,
            data={
                "csrf_token": csrf_token,
                "retpath": "https://passport.yandex.ru/profile",
                "with_code": 1,
            },
        )

        if data.get("status") != "ok":
            raise AuthFailedError(
                "QR session creation failed",
                endpoint=_SUBMIT_URL,
            )

        raw_track_id = data.get("track_id")
        if not isinstance(raw_track_id, str) or not raw_track_id.strip():
            raise AuthFailedError(
                "Passport response missing track_id",
                endpoint=_SUBMIT_URL,
            )
        track_id = raw_track_id.strip()

        csrf_token = str(data.get("csrf_token", csrf_token))
        qr_url = f"{PASSPORT_URL}/auth/magic/code/?track_id={track_id}"

        _log.info("QR session created, track_id=%s", track_id)
        return QrSession(
            track_id=track_id,
            csrf_token=csrf_token,
            qr_url=qr_url,
        )

    async def check_status(self, qr: QrSession) -> bool:
        """Return ``True`` if the QR code was confirmed, ``False`` if pending."""
        data = await self._http.post_json(
            _STATUS_URL,
            data={"csrf_token": qr.csrf_token, "track_id": qr.track_id},
        )
        return bool(data.get("status") == "ok")

    async def get_x_token(self) -> SecretStr:
        """Exchange session cookies for an ``x_token``.

        Must be called after a successful QR confirmation — the
        cookies live in the session's cookie jar.
        """
        passport_url = URL(PASSPORT_URL)
        filtered = self._session.cookie_jar.filter_cookies(passport_url)
        if not filtered:
            raise InvalidCredentialsError(
                "no Yandex session cookies found after QR auth",
                endpoint=_TOKEN_URL,
            )
        cookies = "; ".join(f"{k}={v.value}" for k, v in filtered.items())

        data = await self._http.post_json(
            _TOKEN_URL,
            data={
                "client_id": PASSPORT_CLIENT_ID,
                "client_secret": PASSPORT_CLIENT_SECRET,
            },
            headers={
                "Ya-Client-Host": "passport.yandex.ru",
                "Ya-Client-Cookie": cookies,
            },
        )

        if "access_token" not in data:
            raise InvalidCredentialsError(
                "failed to exchange session for x_token",
                endpoint=_TOKEN_URL,
            )
        return SecretStr(str(data["access_token"]))

    async def get_music_token(self, x_token: SecretStr) -> SecretStr:
        """Exchange an ``x_token`` for a music-scoped OAuth token."""
        data = await self._http.post_json(
            MUSIC_TOKEN_URL,
            data={
                "client_id": MUSIC_CLIENT_ID,
                "client_secret": MUSIC_CLIENT_SECRET,
                "grant_type": "x-token",
                "access_token": x_token.get_secret(),
            },
        )

        if "access_token" not in data:
            raise InvalidCredentialsError(
                "failed to obtain music token from x_token",
                endpoint=MUSIC_TOKEN_URL,
            )
        return SecretStr(str(data["access_token"]))
