"""QR login flow — CSRF extraction, session creation, polling, token exchange.

This module implements the core mobile Passport QR flow:

1. Fetch the ``/am`` page → extract CSRF token from HTML.
2. POST ``/pwl-yandex/api/passport/auth/multistep_start`` with the
   ``X-CSRF-Token`` header → get ``track_id``.
3. POST ``/pwl-yandex/api/passport/auth/password/submit`` with the same
   header and ``with_code=1`` → get a per-track ``csrf_token``.
4. Build a QR URL from ``track_id``; caller displays it.
5. Poll ``/auth/new/magic/status/`` until ``status == "ok"`` using the
   per-track ``csrf_token`` in the form body (legacy endpoint — still
   live and uses the old CSRF mechanism).
6. Exchange session cookies for ``x_token``.
7. Exchange ``x_token`` for ``music_token``.

All network I/O goes through :class:`SafeHttpClient`, so host pinning,
size caps, rate limiting, and error wrapping are automatic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ya_passport_auth.constants import (
    CSRF_PATTERNS,
    PASSPORT_BFF_URL,
    PASSPORT_URL,
)
from ya_passport_auth.credentials import SecretStr
from ya_passport_auth.exceptions import (
    AuthFailedError,
    CsrfExtractionError,
)
from ya_passport_auth.flows._token_exchange import (
    exchange_cookies_for_x_token,
    exchange_x_token_for_music_token,
)
from ya_passport_auth.logging import get_logger

if TYPE_CHECKING:
    import aiohttp

    from ya_passport_auth.http import SafeHttpClient

__all__ = ["QrLoginFlow", "QrSession"]

_log = get_logger("qr")

_AM_URL = f"{PASSPORT_URL}/am?app_platform=android"
_MULTISTEP_URL = f"{PASSPORT_BFF_URL}/auth/multistep_start"
_SUBMIT_URL = f"{PASSPORT_BFF_URL}/auth/password/submit"
_STATUS_URL = f"{PASSPORT_URL}/auth/new/magic/status/"
_RETPATH = f"{PASSPORT_URL}/profile"
_BFF_REFERER = f"{PASSPORT_URL}/pwl-yandex"


@dataclass(frozen=True, slots=True, repr=False)
class QrSession:
    """Opaque handle for an in-progress QR login.

    Callers receive this from :meth:`QrLoginFlow.get_qr` and pass it
    back into :meth:`QrLoginFlow.check_status`. ``qr_url`` is the URL
    to render as a QR code for the user to scan.
    """

    track_id: str
    csrf_token: str
    qr_url: str

    def __repr__(self) -> str:
        # Redact ``csrf_token`` so it never leaks through logs, tracebacks,
        # or REPL ``print`` calls. ``track_id`` and ``qr_url`` are not
        # secrets and are useful for debugging.
        return f"QrSession(track_id={self.track_id!r}, csrf_token='***', qr_url={self.qr_url!r})"


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
        """Fetch CSRF → create QR auth session → return handle.

        Three HTTP steps against the Passport web BFF:

        1. ``GET /am`` → scrape the page CSRF.
        2. ``POST /pwl-yandex/api/passport/auth/multistep_start`` → create
           a new auth track and get ``track_id``.
        3. ``POST /pwl-yandex/api/passport/auth/password/submit`` with
           ``with_code=1`` → convert the track into a magic-link session
           and receive a per-track ``csrf_token`` used by the polling
           endpoint.
        """
        html = await self._http.get_text(_AM_URL)
        page_csrf = _extract_csrf(html)

        bff_headers = {
            "X-CSRF-Token": page_csrf,
            "Origin": PASSPORT_URL,
            "Referer": _BFF_REFERER,
        }

        # Step 1: start a new auth track.
        start_data = await self._http.post_json(
            _MULTISTEP_URL,
            data={},
            headers=bff_headers,
        )
        raw_track_id = start_data.get("track_id")
        if not isinstance(raw_track_id, str) or not raw_track_id.strip():
            raise AuthFailedError(
                "multistep_start response missing track_id",
                endpoint=_MULTISTEP_URL,
            )
        track_id = raw_track_id.strip()

        # Step 2: convert the track into a QR/magic-link session.
        submit_data = await self._http.post_json(
            _SUBMIT_URL,
            data={
                "track_id": track_id,
                "with_code": "1",
                "retpath": _RETPATH,
            },
            headers=bff_headers,
        )
        submit_status = submit_data.get("status")
        if isinstance(submit_status, str) and submit_status != "ok":
            raise AuthFailedError(
                f"QR session creation failed (status={submit_status!r})",
                endpoint=_SUBMIT_URL,
            )

        raw_csrf = submit_data.get("csrf_token")
        if not isinstance(raw_csrf, str) or not raw_csrf.strip():
            raise AuthFailedError(
                "password/submit response missing csrf_token",
                endpoint=_SUBMIT_URL,
            )
        csrf_token = raw_csrf.strip()

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
        return await exchange_cookies_for_x_token(self._http, self._session)

    async def get_music_token(self, x_token: SecretStr) -> SecretStr:
        """Exchange an ``x_token`` for a music-scoped OAuth token."""
        return await exchange_x_token_for_music_token(self._http, x_token)
