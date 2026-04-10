"""Account info and x_token validation via ``short_info`` endpoint."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ya_passport_auth.constants import PASSPORT_API_URL
from ya_passport_auth.credentials import SecretStr
from ya_passport_auth.exceptions import AuthFailedError, InvalidCredentialsError
from ya_passport_auth.logging import get_logger
from ya_passport_auth.models import AccountInfo

if TYPE_CHECKING:
    from ya_passport_auth.http import SafeHttpClient

__all__ = ["AccountInfoFetcher"]

_log = get_logger("account")

_SHORT_INFO_URL = f"{PASSPORT_API_URL}/1/bundle/account/short_info/"


class AccountInfoFetcher:
    """Fetch account metadata and validate x_tokens."""

    __slots__ = ("_http",)

    def __init__(self, *, http: SafeHttpClient) -> None:
        self._http = http

    async def fetch(self, x_token: SecretStr) -> AccountInfo:
        """Return account info for the given ``x_token``."""
        data = await self._http.get_json(
            _SHORT_INFO_URL,
            headers={"Authorization": f"OAuth {x_token.get_secret()}"},
        )

        status_code = data.get("status_code")
        if isinstance(status_code, int) and status_code in (401, 403):
            raise InvalidCredentialsError(
                "x_token rejected by short_info",
                status_code=status_code,
                endpoint=_SHORT_INFO_URL,
            )

        raw_uid = data.get("uid")
        if raw_uid is None:
            raise AuthFailedError(
                "short_info response missing uid",
                endpoint=_SHORT_INFO_URL,
            )

        return AccountInfo(
            uid=int(str(raw_uid)),
            display_login=_str_or_none(data.get("display_login")),
            display_name=_str_or_none(data.get("display_name")),
            public_id=_str_or_none(data.get("public_id")),
        )

    async def validate(self, x_token: SecretStr) -> bool:
        """Return ``True`` if the ``x_token`` is valid, ``False`` otherwise."""
        try:
            await self.fetch(x_token)
        except (InvalidCredentialsError, AuthFailedError):
            return False
        return True


def _str_or_none(val: object) -> str | None:
    return str(val) if val is not None else None
