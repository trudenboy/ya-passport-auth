"""Quasar CSRF token fetcher."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ya_passport_auth.credentials import SecretStr
from ya_passport_auth.exceptions import CsrfExtractionError
from ya_passport_auth.logging import get_logger

if TYPE_CHECKING:
    from ya_passport_auth.http import SafeHttpClient

__all__ = ["QuasarCsrfFetcher"]

_log = get_logger("quasar")

_DEVICES_URL = "https://iot.quasar.yandex.ru/m/v3/user/devices"


class QuasarCsrfFetcher:
    """Fetch a Quasar CSRF token from the ``x-csrf-token`` response header."""

    __slots__ = ("_http",)

    def __init__(self, *, http: SafeHttpClient) -> None:
        self._http = http

    async def fetch(self) -> SecretStr:
        """GET the devices endpoint and extract the CSRF header."""
        _data, headers = await self._http.get_json_with_headers(_DEVICES_URL)

        csrf = headers.get("x-csrf-token")
        if not csrf:
            raise CsrfExtractionError(
                "x-csrf-token header missing from Quasar response",
                endpoint=_DEVICES_URL,
            )
        return SecretStr(csrf)
