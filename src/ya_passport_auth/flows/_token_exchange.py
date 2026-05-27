"""Shared token-exchange helpers used by multiple auth flows.

Extracts cookies → x_token and x_token → music_token logic so it can
be reused by QR and cookie-based login flows.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from yarl import URL

from ya_passport_auth.constants import (
    MUSIC_CLIENT_ID,
    MUSIC_CLIENT_SECRET,
    MUSIC_TOKEN_URL,
    PASSPORT_CLIENT_ID,
    PASSPORT_CLIENT_SECRET,
    PASSPORT_TOKEN_BY_SESSIONID_URL,
    PASSPORT_URL,
)
from ya_passport_auth.credentials import SecretStr
from ya_passport_auth.exceptions import InvalidCredentialsError
from ya_passport_auth.logging import get_logger

if TYPE_CHECKING:
    import aiohttp

    from ya_passport_auth.http import SafeHttpClient

__all__ = [
    "exchange_cookie_string_for_x_token",
    "exchange_cookies_for_x_token",
    "exchange_x_token_for_music_token",
    "format_token_error",
]

_log = get_logger("token_exchange")


def format_token_error(prefix: str, data: dict[str, object]) -> str:
    """Append server-provided error markers to *prefix*, when present.

    ``token_by_sessionid`` signals failure via
    ``{"status": "error", "errors": ["sessionid.invalid"]}``; surfacing
    that marker makes "wrong cookie" diagnostics dramatically easier.
    Also handles the simpler ``{"error": "invalid_grant"}`` shape used
    elsewhere by the OAuth endpoints.
    """
    errors = data.get("errors")
    if isinstance(errors, list) and errors:
        markers = ", ".join(str(e) for e in errors if isinstance(e, (str, int)))
        if markers:
            return f"{prefix}: {markers}"
    err = data.get("error")
    if isinstance(err, str) and err:
        return f"{prefix}: {err}"
    return prefix


def _extract_cookie_header(session: aiohttp.ClientSession) -> str:
    """Build ``Ya-Client-Cookie`` value from the session's cookie jar.

    Strips CR/LF from cookie values to prevent HTTP header injection (T12).
    """
    passport_url = URL(PASSPORT_URL)
    filtered = session.cookie_jar.filter_cookies(passport_url)
    if not filtered:
        raise InvalidCredentialsError(
            "no Yandex session cookies found",
            endpoint=PASSPORT_TOKEN_BY_SESSIONID_URL,
        )

    def _sanitize(val: str) -> str:
        return val.replace(chr(13), "").replace(chr(10), "")

    return "; ".join(f"{k}={_sanitize(v.value)}" for k, v in filtered.items())


async def _post_token_by_sessionid(
    http: SafeHttpClient,
    cookie_header: str,
    *,
    error_prefix: str,
) -> SecretStr:
    """POST to ``token_by_sessionid`` with the given ``Ya-Client-Cookie`` value.

    Shared between :func:`exchange_cookies_for_x_token` (cookies from
    the session jar) and :func:`exchange_cookie_string_for_x_token`
    (cookies supplied by the caller). Both paths POST identical bodies
    and headers; only the cookie source and the diagnostic prefix differ.
    """
    data = await http.post_json(
        PASSPORT_TOKEN_BY_SESSIONID_URL,
        data={
            "client_id": PASSPORT_CLIENT_ID,
            "client_secret": PASSPORT_CLIENT_SECRET,
        },
        headers={
            "Ya-Client-Host": "passport.yandex.ru",
            "Ya-Client-Cookie": cookie_header,
        },
    )

    if "access_token" not in data:
        raise InvalidCredentialsError(
            format_token_error(error_prefix, data),
            endpoint=PASSPORT_TOKEN_BY_SESSIONID_URL,
        )
    return SecretStr(str(data["access_token"]))


async def exchange_cookies_for_x_token(
    http: SafeHttpClient,
    session: aiohttp.ClientSession,
) -> SecretStr:
    """Exchange session cookies for an ``x_token``.

    The cookies must already be present in the session's cookie jar
    (placed there by a successful QR confirmation or session refresh).
    """
    cookie_header = _extract_cookie_header(session)
    token = await _post_token_by_sessionid(
        http,
        cookie_header,
        error_prefix="failed to exchange session for x_token",
    )
    _log.info("Session cookies exchanged for x_token")
    return token


async def exchange_cookie_string_for_x_token(
    http: SafeHttpClient,
    cookies: str,
) -> SecretStr:
    """Exchange a caller-supplied cookie string for an ``x_token``.

    *cookies* is a semicolon-separated ``key=value`` string
    (e.g. ``"Session_id=abc; sessionid2=def"``). CR/LF characters are
    stripped to defeat header injection (T12).

    Raises :class:`InvalidCredentialsError` for empty input or a server
    rejection.
    """
    if not cookies or not cookies.strip():
        raise InvalidCredentialsError(
            "cookie string is empty",
            endpoint=PASSPORT_TOKEN_BY_SESSIONID_URL,
        )

    sanitized = cookies.strip().replace("\r", "").replace("\n", "")
    token = await _post_token_by_sessionid(
        http,
        sanitized,
        error_prefix="failed to exchange cookies for x_token",
    )
    _log.info("cookies exchanged for x_token")
    return token


async def exchange_x_token_for_music_token(
    http: SafeHttpClient,
    x_token: SecretStr,
) -> SecretStr:
    """Exchange an ``x_token`` for a music-scoped OAuth token."""
    data = await http.post_json(
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
    _log.info("x_token exchanged for music_token")
    return SecretStr(str(data["access_token"]))
