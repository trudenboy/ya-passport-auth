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

# The dedicated CSRF endpoint on the Quasar web frontend. It returns
# ``{"status": "ok", "token": "<csrf>"}`` when called with a refreshed
# Passport session (the ``Session_id``/``sessionid2`` cookies set by
# ``PassportSessionRefresher``).
_CSRF_TOKEN_URL = "https://quasar.yandex.ru/csrf_token"


class QuasarCsrfFetcher:
    """Fetch a Quasar CSRF token from the dedicated ``csrf_token`` endpoint."""

    __slots__ = ("_http",)

    def __init__(self, *, http: SafeHttpClient) -> None:
        self._http = http

    async def fetch(self) -> SecretStr:
        """GET the CSRF endpoint and return the parsed ``token`` field."""
        data = await self._http.get_json(_CSRF_TOKEN_URL)

        if data.get("status") != "ok":
            raise CsrfExtractionError(
                "Quasar csrf_token endpoint returned non-ok status",
                endpoint=_CSRF_TOKEN_URL,
            )

        raw_token = data.get("token")
        if not isinstance(raw_token, str) or not raw_token.strip():
            raise CsrfExtractionError(
                "Quasar csrf_token response missing token field",
                endpoint=_CSRF_TOKEN_URL,
            )
        return SecretStr(raw_token.strip())
