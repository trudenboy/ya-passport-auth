"""Shared token-exchange helpers used by multiple auth flows.

Extracts cookies → x_token and x_token → music_token logic so it can
be reused by QR, password, and cookie-based login flows.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from yarl import URL

from ya_passport_auth.constants import (
    MUSIC_CLIENT_ID,
    MUSIC_CLIENT_SECRET,
    MUSIC_TOKEN_URL,
    PASSPORT_API_URL,
    PASSPORT_CLIENT_ID,
    PASSPORT_CLIENT_SECRET,
    PASSPORT_URL,
)
from ya_passport_auth.credentials import SecretStr
from ya_passport_auth.exceptions import InvalidCredentialsError
from ya_passport_auth.logging import get_logger

if TYPE_CHECKING:
    import aiohttp

    from ya_passport_auth.http import SafeHttpClient

__all__ = ["exchange_cookies_for_x_token", "exchange_x_token_for_music_token"]

_log = get_logger("token_exchange")

_TOKEN_URL = f"{PASSPORT_API_URL}/1/bundle/oauth/token_by_sessionid"


def _extract_cookie_header(session: aiohttp.ClientSession) -> str:
    """Build ``Ya-Client-Cookie`` value from the session's cookie jar.

    Strips CR/LF from cookie values to prevent HTTP header injection (T12).
    """
    passport_url = URL(PASSPORT_URL)
    filtered = session.cookie_jar.filter_cookies(passport_url)
    if not filtered:
        raise InvalidCredentialsError(
            "no Yandex session cookies found",
            endpoint=_TOKEN_URL,
        )
    return "; ".join(
        f"{k}={v.value.replace(chr(13), '').replace(chr(10), '')}" for k, v in filtered.items()
    )


async def exchange_cookies_for_x_token(
    http: SafeHttpClient,
    session: aiohttp.ClientSession,
) -> SecretStr:
    """Exchange session cookies for an ``x_token``.

    The cookies must already be present in the session's cookie jar
    (placed there by a successful QR confirmation, password login, etc.).
    """
    cookies = _extract_cookie_header(session)

    data = await http.post_json(
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
    return SecretStr(str(data["access_token"]))
