"""Glagol device token fetcher for Yandex Station speakers."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlencode

from ya_passport_auth.credentials import SecretStr
from ya_passport_auth.exceptions import InvalidCredentialsError
from ya_passport_auth.logging import get_logger

if TYPE_CHECKING:
    from ya_passport_auth.http import SafeHttpClient

__all__ = ["GlagolDeviceTokenFetcher"]

_log = get_logger("glagol")

_GLAGOL_URL = "https://quasar.yandex.net/glagol/token"


class GlagolDeviceTokenFetcher:
    """Fetch a local-network Glagol token for a Yandex Station device."""

    __slots__ = ("_http",)

    def __init__(self, *, http: SafeHttpClient) -> None:
        self._http = http

    async def fetch(
        self,
        *,
        music_token: SecretStr,
        device_id: str,
        platform: str,
    ) -> SecretStr:
        """GET the glagol token endpoint with the music OAuth token."""
        url = f"{_GLAGOL_URL}?{urlencode({'device_id': device_id, 'platform': platform})}"
        data = await self._http.get_json(
            url,
            headers={"Authorization": f"OAuth {music_token.get_secret()}"},
        )

        # 401/403 are already caught by SafeHttpClient (it raises
        # NetworkError), but the endpoint may return a 200 with an error body.
        token = data.get("token")
        if not token:
            raise InvalidCredentialsError(
                "glagol token missing from response",
                endpoint=_GLAGOL_URL,
            )
        return SecretStr(str(token))
