"""Cookie-based login — exchange browser cookies directly for an x_token.

When a user imports cookies from a browser session or provides them
externally, the library can bypass the interactive login entirely and
exchange the cookies directly for an ``x_token``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ya_passport_auth.constants import (
    PASSPORT_API_URL,
    PASSPORT_CLIENT_ID,
    PASSPORT_CLIENT_SECRET,
)
from ya_passport_auth.credentials import SecretStr
from ya_passport_auth.exceptions import InvalidCredentialsError
from ya_passport_auth.logging import get_logger

if TYPE_CHECKING:
    from ya_passport_auth.http import SafeHttpClient

__all__ = ["CookieLoginFlow"]

_log = get_logger("cookie_login")

_TOKEN_URL = f"{PASSPORT_API_URL}/1/bundle/oauth/token_by_sessionid"


class CookieLoginFlow:
    """Exchange raw cookies for an ``x_token`` without interactive login."""

    __slots__ = ("_http",)

    def __init__(self, *, http: SafeHttpClient) -> None:
        self._http = http

    async def login(self, cookies: str) -> SecretStr:
        """Exchange a cookie string for an ``x_token``.

        *cookies* should be a semicolon-separated ``key=value`` string
        (e.g. ``"Session_id=abc; sessionid2=def"``).

        Raises :class:`InvalidCredentialsError` if the cookies are
        rejected by the server.
        """
        if not cookies or not cookies.strip():
            raise InvalidCredentialsError(
                "cookie string is empty",
                endpoint=_TOKEN_URL,
            )

        data = await self._http.post_json(
            _TOKEN_URL,
            data={
                "client_id": PASSPORT_CLIENT_ID,
                "client_secret": PASSPORT_CLIENT_SECRET,
            },
            headers={
                "Ya-Client-Host": "passport.yandex.ru",
                "Ya-Client-Cookie": cookies.strip(),
            },
        )

        if "access_token" not in data:
            raise InvalidCredentialsError(
                "failed to exchange cookies for x_token",
                endpoint=_TOKEN_URL,
            )
        _log.info("cookies exchanged for x_token")
        return SecretStr(str(data["access_token"]))
