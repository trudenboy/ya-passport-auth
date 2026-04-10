"""Passport cookie refresh via ``x_token``."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ya_passport_auth.constants import PASSPORT_API_URL, PASSPORT_URL
from ya_passport_auth.credentials import SecretStr
from ya_passport_auth.exceptions import InvalidCredentialsError
from ya_passport_auth.logging import get_logger

if TYPE_CHECKING:
    from ya_passport_auth.http import SafeHttpClient

__all__ = ["PassportSessionRefresher"]

_log = get_logger("session")

_AUTH_URL = f"{PASSPORT_API_URL}/1/bundle/auth/x_token/"
_SESSION_URL = f"{PASSPORT_URL}/auth/session/"


class PassportSessionRefresher:
    """Refresh Passport session cookies from an ``x_token``.

    Two-step flow:
    1. POST ``x_token`` to the bundle auth endpoint → get ``track_id``.
    2. GET the session endpoint with the ``track_id`` → cookies land
       in the session jar.
    """

    __slots__ = ("_http",)

    def __init__(
        self,
        *,
        http: SafeHttpClient,
    ) -> None:
        self._http = http

    async def refresh(self, x_token: SecretStr) -> None:
        """Refresh Passport session cookies from the given ``x_token``."""
        data = await self._http.post_json(
            _AUTH_URL,
            data={"type": "x-token", "retpath": PASSPORT_URL},
            headers={"Ya-Consumer-Authorization": f"OAuth {x_token.get_secret()}"},
        )

        if data.get("status") != "ok":
            raise InvalidCredentialsError(
                "x_token auth bundle failed",
                endpoint=_AUTH_URL,
            )

        raw_track_id = data.get("track_id")
        if not isinstance(raw_track_id, str) or not raw_track_id.strip():
            raise InvalidCredentialsError(
                "x_token auth bundle missing track_id",
                endpoint=_AUTH_URL,
            )

        track_id = raw_track_id.strip()

        # Always use the well-known session URL. The ``passport_host``
        # field in the response body is attacker-controllable and could
        # be used as an SSRF vector (T4) — ignore it entirely.
        _log.info("refreshing session cookies via track_id")
        await self._http.get_text(
            _SESSION_URL,
            headers={"track_id": track_id},
        )
