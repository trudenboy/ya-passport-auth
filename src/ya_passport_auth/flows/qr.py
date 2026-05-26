"""QR login flow — CSRF extraction, session creation, polling, token exchange.

This module implements the mobile Passport QR flow against the
``/pwl-yandex`` BFF:

1. ``GET /pwl-yandex`` → extract page CSRF from HTML.
2. ``POST /pwl-yandex/api/passport/auth/password/submit`` (JSON body
   ``{"retpath": ...}``, ``X-CSRF-Token`` header) → opaque ``auth_state``
   carrying ``track_id``.
3. ``POST /pwl-yandex/api/passport/auth/magic/code`` (form-data with
   ``magic_track_id``) → server-provided ``link`` (the QR URL).
4. *Polling*: ``POST /pwl-yandex/api/passport/auth/magic/code/status``
   (JSON body = the ``auth_state``). Passport returns an empty object
   ``{}`` while the QR is unscanned and
   ``{"state": "otp_auth_finished", "trackId": "..."}`` once the user
   confirms on phone. Any other non-confirmed state is treated as
   pending as well.
5. ``POST /pwl-yandex/api/passport/sessions/get_session`` (form-data
   ``track_id``) → cookies land in the session jar.

After step 5 the caller continues with the standard cookies →
``x_token`` → ``music_token`` exchange.

All network I/O goes through :class:`SafeHttpClient`, so host pinning,
size caps, rate limiting, and error wrapping are automatic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from yarl import URL

from ya_passport_auth.constants import (
    CSRF_PATTERNS,
    PASSPORT_BFF_URL,
    PASSPORT_URL,
)
from ya_passport_auth.exceptions import (
    AuthFailedError,
    CsrfExtractionError,
)
from ya_passport_auth.logging import get_logger

if TYPE_CHECKING:
    import aiohttp

    from ya_passport_auth.config import ClientConfig
    from ya_passport_auth.http import SafeHttpClient

__all__ = ["QrLoginFlow", "QrSession"]

_log = get_logger("qr")

_AM_URL = f"{PASSPORT_URL}/pwl-yandex"
_SUBMIT_URL = f"{PASSPORT_BFF_URL}/auth/password/submit"
_MAGIC_CODE_URL = f"{PASSPORT_BFF_URL}/auth/magic/code"
_STATUS_URL = f"{PASSPORT_BFF_URL}/auth/magic/code/status"
_GET_SESSION_URL = f"{PASSPORT_BFF_URL}/sessions/get_session"
_RETPATH = f"{PASSPORT_URL}/profile"
_BFF_REFERER = f"{PASSPORT_URL}/pwl-yandex"

_STATE_CONFIRMED = "otp_auth_finished"


@dataclass(frozen=True, slots=True, repr=False)
class QrSession:
    """Opaque handle for an in-progress QR login.

    Callers receive this from :meth:`QrLoginFlow.get_qr` and pass it
    back into :meth:`QrLoginFlow.check_status`. ``qr_url`` is the URL
    to render as a QR code for the user to scan.

    ``auth_state`` is internal server-issued state passed back to the
    polling endpoint; it is opaque to callers and redacted in ``repr``.
    """

    track_id: str
    csrf_token: str
    qr_url: str
    auth_state: tuple[tuple[str, object], ...] = field(default=())

    def __repr__(self) -> str:
        # Redact ``csrf_token`` and ``auth_state`` so neither leaks
        # through logs, tracebacks, or REPL ``print`` calls.
        # ``track_id`` and ``qr_url`` are not secrets and are useful
        # for debugging.
        return (
            f"QrSession(track_id={self.track_id!r}, csrf_token='***', "
            f"qr_url={self.qr_url!r}, auth_state='***')"
        )


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


def _require_str(payload: dict[str, object], key: str, endpoint: str) -> str:
    """Pull *key* from *payload* and require it to be a non-empty string."""
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise AuthFailedError(
            f"response missing {key!r}",
            endpoint=endpoint,
        )
    return value.strip()


class QrLoginFlow:
    """Low-level QR login steps.

    Each method maps to one Yandex flow stage. The higher-level
    :class:`PassportClient` composes these into a full flow with
    polling and timeout logic.
    """

    __slots__ = ("_allowed_hosts", "_http", "_session")

    def __init__(
        self,
        *,
        http: SafeHttpClient,
        session: aiohttp.ClientSession,
        config: ClientConfig,
    ) -> None:
        self._http = http
        self._session = session
        self._allowed_hosts = config.allowed_hosts

    async def get_qr(self) -> QrSession:
        """Fetch CSRF → create QR auth session → return handle.

        Three HTTP steps against the ``/pwl-yandex`` BFF:

        1. ``GET /pwl-yandex`` → scrape the page CSRF.
        2. ``POST /pwl-yandex/api/passport/auth/password/submit`` with
           a JSON body ``{"retpath": ...}`` and the page CSRF in the
           ``X-CSRF-Token`` header → server returns an opaque
           ``auth_state`` carrying a ``track_id``.
        3. ``POST /pwl-yandex/api/passport/auth/magic/code`` with the
           ``magic_track_id`` → server returns a ``link`` to encode as
           the QR code.
        """
        html = await self._http.get_text(_AM_URL)
        page_csrf = _extract_csrf(html)

        bff_headers = {
            "X-CSRF-Token": page_csrf,
            "Origin": PASSPORT_URL,
            "Referer": _BFF_REFERER,
        }

        auth_state = await self._http.post_json(
            _SUBMIT_URL,
            json={"retpath": _RETPATH},
            headers=bff_headers,
        )
        track_id = _require_str(auth_state, "track_id", _SUBMIT_URL)

        magic_resp = await self._http.post_json(
            _MAGIC_CODE_URL,
            data={
                "location_id": "0",
                "magic_track_id": track_id,
                "track_id": "",
            },
            headers=bff_headers,
        )
        link = _require_str(magic_resp, "link", _MAGIC_CODE_URL)
        self._validate_link(link)

        _log.info("QR session created, track_id=%s", track_id)
        return QrSession(
            track_id=track_id,
            csrf_token=page_csrf,
            qr_url=link,
            auth_state=tuple(auth_state.items()),
        )

    async def check_status(self, qr: QrSession) -> bool:
        """Return ``True`` if the QR code was confirmed, ``False`` if pending.

        On confirmation, also calls ``sessions/get_session`` to deposit
        session cookies into the jar before returning — so the caller can
        proceed directly to ``exchange_cookies_for_x_token``.

        Raises :class:`AuthFailedError` if *qr* was not produced by
        :meth:`get_qr` (empty ``auth_state``) or if the server response
        is missing the ``state`` field — silently treating malformed
        responses as pending would mask upstream errors as timeouts.
        """
        if not qr.auth_state:
            raise AuthFailedError(
                "check_status called with empty auth_state — was QrSession produced by get_qr()?",
                endpoint=_STATUS_URL,
            )

        headers = {"X-CSRF-Token": qr.csrf_token}
        status_resp = await self._http.post_json(
            _STATUS_URL,
            json=dict(qr.auth_state),
            headers=headers,
        )
        # Passport now returns `{}` while the QR is unscanned; the previous
        # "must contain state" rule aborted the very first poll and made
        # QR login impossible. Treat absent/empty/non-confirmation state
        # as pending; only the confirmation marker advances.
        state = status_resp.get("state")
        if not isinstance(state, str) or state != _STATE_CONFIRMED:
            return False

        session_track_id = _require_str(status_resp, "trackId", _STATUS_URL)
        await self._http.post_json(
            _GET_SESSION_URL,
            data={"track_id": session_track_id},
            headers=headers,
        )
        _log.info("QR confirmed, session cookies deposited")
        return True

    def _validate_link(self, link: str) -> None:
        """Reject ``link`` if its scheme/host fall outside the allow-list.

        Defence-in-depth (T4): the QR URL is rendered to the user and
        scanned by their phone. A malicious server could substitute a
        phishing URL, so we constrain it to HTTPS hosts we already trust.
        """
        try:
            parsed = URL(link)
        except (TypeError, ValueError) as exc:
            raise AuthFailedError(
                "magic/code returned an unparseable link",
                endpoint=_MAGIC_CODE_URL,
            ) from exc
        if parsed.scheme != "https":
            raise AuthFailedError(
                f"magic/code link uses non-HTTPS scheme {parsed.scheme!r}",
                endpoint=_MAGIC_CODE_URL,
            )
        host = parsed.host
        if host is None or host not in self._allowed_hosts:
            raise AuthFailedError(
                f"magic/code link host {host!r} is not in the allow-list",
                endpoint=_MAGIC_CODE_URL,
            )
