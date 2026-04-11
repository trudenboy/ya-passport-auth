"""Password login flow — multi-step auth with SMS, magic link, and captcha.

This module implements Yandex's legacy ``/registration-validations/``
multi-step authentication:

1. ``start_auth`` — fetch CSRF from ``/am``, POST ``multi_step/start``
   with the username → get ``track_id`` and available auth methods.
2a. ``submit_password`` — POST ``commit_password`` with the password.
2b. ``request_sms`` / ``submit_sms`` — phone-based fallback.
2c. ``request_magic_link`` / ``check_magic_link`` — email-based fallback.
3. ``get_captcha`` / ``submit_captcha`` — solve CAPTCHA if required.

After any successful auth step, session cookies are in the jar and can
be exchanged for ``x_token`` via :func:`exchange_cookies_for_x_token`.

All network I/O goes through :class:`SafeHttpClient`, so host pinning,
size caps, rate limiting, and error wrapping are automatic.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ya_passport_auth.constants import (
    CSRF_PATTERNS,
    PASSPORT_LEGACY_URL,
    PASSPORT_URL,
)
from ya_passport_auth.exceptions import (
    AccountNotFoundError,
    AuthFailedError,
    CaptchaRequiredError,
    CsrfExtractionError,
    PasswordError,
)
from ya_passport_auth.logging import get_logger
from ya_passport_auth.models import AuthSession, CaptchaChallenge

if TYPE_CHECKING:
    from ya_passport_auth.http import SafeHttpClient

__all__ = ["PasswordLoginFlow"]

_log = get_logger("password")

_AM_URL = f"{PASSPORT_URL}/am?app_platform=android"
_START_URL = f"{PASSPORT_LEGACY_URL}/auth/multi_step/start"
_PASSWORD_URL = f"{PASSPORT_LEGACY_URL}/auth/multi_step/commit_password"
_SMS_REQUEST_URL = f"{PASSPORT_LEGACY_URL}/phone-confirm-code-submit"
_SMS_VERIFY_URL = f"{PASSPORT_LEGACY_URL}/phone-confirm-code"
_SMS_COMMIT_URL = f"{PASSPORT_LEGACY_URL}/multi-step-commit-sms-code"
_MAGIC_SEND_URL = f"{PASSPORT_LEGACY_URL}/auth/send_magic_letter"
_MAGIC_STATUS_URL = f"{PASSPORT_URL}/auth/letter/status/"
_CAPTCHA_GET_URL = f"{PASSPORT_LEGACY_URL}/textcaptcha"
_CAPTCHA_CHECK_URL = f"{PASSPORT_LEGACY_URL}/checkHuman"
_RETPATH = f"{PASSPORT_URL}/profile"


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


class PasswordLoginFlow:
    """Low-level multi-step password login.

    Each method maps to one or two HTTP round-trips. The higher-level
    :class:`PassportClient` composes these into a full flow with
    token exchange and account info lookup.
    """

    __slots__ = ("_http",)

    def __init__(self, *, http: SafeHttpClient) -> None:
        self._http = http

    async def start_auth(self, username: str) -> AuthSession:
        """Begin multi-step auth: fetch CSRF, submit username, get track.

        Returns an :class:`AuthSession` with ``track_id`` and available
        ``auth_methods``.

        Raises :class:`AccountNotFoundError` if the username cannot
        authorize (``can_authorize`` is false).
        """
        html = await self._http.get_text(_AM_URL)
        csrf_token = _extract_csrf(html)

        data = await self._http.post_json(
            _START_URL,
            data={"csrf_token": csrf_token, "login": username},
        )
        status = data.get("status")
        if status != "ok":
            raise AuthFailedError(
                f"multi_step/start failed (status={status!r})",
                endpoint=_START_URL,
            )

        can_authorize = data.get("can_authorize", False)
        if not can_authorize:
            raise AccountNotFoundError(
                "account cannot authorize (registration required)",
                endpoint=_START_URL,
            )

        raw_track_id = data.get("track_id")
        if not isinstance(raw_track_id, str) or not raw_track_id.strip():
            raise AuthFailedError(
                "multi_step/start response missing track_id",
                endpoint=_START_URL,
            )
        track_id = raw_track_id.strip()

        raw_methods = data.get("auth_methods", [])
        auth_methods = tuple(str(m) for m in raw_methods) if isinstance(raw_methods, list) else ()

        raw_email = data.get("magic_link_email")
        magic_link_email = str(raw_email) if isinstance(raw_email, str) else None

        _log.info("auth started for track_id=%s, methods=%s", track_id, auth_methods)
        return AuthSession(
            track_id=track_id,
            csrf_token=csrf_token,
            auth_methods=auth_methods,
            magic_link_email=magic_link_email,
        )

    async def submit_password(self, auth: AuthSession, password: str) -> None:
        """Submit a password for the given auth session.

        On success, session cookies are placed in the cookie jar.

        Raises :class:`PasswordError` if the password is wrong.
        Raises :class:`CaptchaRequiredError` if CAPTCHA is needed.
        """
        data = await self._http.post_json(
            _PASSWORD_URL,
            data={
                "csrf_token": auth.csrf_token,
                "track_id": auth.track_id,
                "password": password,
                "retpath": _RETPATH,
            },
        )
        status = data.get("status")
        if isinstance(status, str) and status == "ok":
            _log.info("password accepted for track_id=%s", auth.track_id)
            return

        errors = data.get("errors")
        if isinstance(errors, list):
            error_list = [str(e) for e in errors]
            if "captcha.required" in error_list:
                raise CaptchaRequiredError(
                    "captcha required before password auth can proceed",
                    endpoint=_PASSWORD_URL,
                )
            if "password.not_matched" in error_list:
                raise PasswordError(
                    "wrong password",
                    endpoint=_PASSWORD_URL,
                )

        if data.get("redirect_url"):
            raise AuthFailedError(
                "unexpected redirect during password auth",
                endpoint=_PASSWORD_URL,
            )

        raise AuthFailedError(
            f"password auth failed (status={status!r})",
            endpoint=_PASSWORD_URL,
        )

    async def request_sms(self, auth: AuthSession) -> None:
        """Request an SMS code for the given auth session."""
        data = await self._http.post_json(
            _SMS_REQUEST_URL,
            data={
                "csrf_token": auth.csrf_token,
                "track_id": auth.track_id,
                "mode": "tracked",
            },
        )
        status = data.get("status")
        if status != "ok":
            raise AuthFailedError(
                f"SMS request failed (status={status!r})",
                endpoint=_SMS_REQUEST_URL,
            )
        _log.info("SMS code requested for track_id=%s", auth.track_id)

    async def submit_sms(self, auth: AuthSession, code: str) -> None:
        """Verify an SMS code and commit the auth session.

        Two-step process: verify the code, then commit.
        On success, session cookies are placed in the cookie jar.
        """
        verify_data = await self._http.post_json(
            _SMS_VERIFY_URL,
            data={
                "csrf_token": auth.csrf_token,
                "track_id": auth.track_id,
                "mode": "tracked",
                "code": code,
            },
        )
        verify_status = verify_data.get("status")
        if verify_status != "ok":
            raise AuthFailedError(
                f"SMS code verification failed (status={verify_status!r})",
                endpoint=_SMS_VERIFY_URL,
            )

        commit_data = await self._http.post_json(
            _SMS_COMMIT_URL,
            data={
                "csrf_token": auth.csrf_token,
                "track_id": auth.track_id,
                "retpath": _RETPATH,
            },
        )
        commit_status = commit_data.get("status")
        if commit_status != "ok":
            raise AuthFailedError(
                f"SMS commit failed (status={commit_status!r})",
                endpoint=_SMS_COMMIT_URL,
            )
        _log.info("SMS auth completed for track_id=%s", auth.track_id)

    async def request_magic_link(self, auth: AuthSession) -> None:
        """Send a magic-link confirmation email."""
        data = await self._http.post_json(
            _MAGIC_SEND_URL,
            data={
                "csrf_token": auth.csrf_token,
                "track_id": auth.track_id,
            },
        )
        status = data.get("status")
        if status != "ok":
            raise AuthFailedError(
                f"magic link request failed (status={status!r})",
                endpoint=_MAGIC_SEND_URL,
            )
        _log.info("magic link sent for track_id=%s", auth.track_id)

    async def check_magic_link(self, auth: AuthSession) -> bool:
        """Check whether the magic link has been confirmed.

        Returns ``True`` if confirmed (cookies now in jar),
        ``False`` if still pending.

        Raises :class:`AuthFailedError` on server error responses.
        """
        data = await self._http.post_json(
            _MAGIC_STATUS_URL,
            data={
                "csrf_token": auth.csrf_token,
                "track_id": auth.track_id,
            },
        )
        status = data.get("status")
        if not isinstance(status, str):
            raise AuthFailedError(
                "magic link check response missing or invalid status",
                endpoint=_MAGIC_STATUS_URL,
            )
        if status == "magic_link_confirmed":
            _log.info("magic link confirmed for track_id=%s", auth.track_id)
            return True
        if status in ("PENDING", "pending"):
            return False
        raise AuthFailedError(
            f"magic link check failed (status={status!r})",
            endpoint=_MAGIC_STATUS_URL,
        )

    async def get_captcha(self, auth: AuthSession) -> CaptchaChallenge:
        """Fetch a CAPTCHA image that must be solved before retrying auth."""
        data = await self._http.post_json(
            _CAPTCHA_GET_URL,
            data={
                "csrf_token": auth.csrf_token,
                "track_id": auth.track_id,
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        raw_url = data.get("captcha_url")
        raw_key = data.get("key")
        if not isinstance(raw_url, str) or not isinstance(raw_key, str):
            raise AuthFailedError(
                "captcha response missing captcha_url or key",
                endpoint=_CAPTCHA_GET_URL,
            )
        return CaptchaChallenge(image_url=raw_url, key=raw_key)

    async def submit_captcha(
        self,
        auth: AuthSession,
        challenge: CaptchaChallenge,
        answer: str,
    ) -> bool:
        """Submit a CAPTCHA answer. Returns ``True`` if accepted."""
        data = await self._http.post_json(
            _CAPTCHA_CHECK_URL,
            data={
                "csrf_token": auth.csrf_token,
                "track_id": auth.track_id,
                "key": challenge.key,
                "answer": answer,
            },
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        return bool(data.get("status") == "ok")
