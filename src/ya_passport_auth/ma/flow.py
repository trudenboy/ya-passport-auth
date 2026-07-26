"""Cookie login and shared error mapping for Music Assistant config actions.

``login_with_cookies`` wraps :class:`~ya_passport_auth.PassportClient` with
unified MA error mapping; ``require_music_token`` extracts the music token
from a completed login's credentials or raises a uniform error.

Interactive device/QR login is the caller's responsibility: MA's setup flows
drive :class:`~ya_passport_auth.PassportClient` directly (``start_device_login``,
``poll_device_until_confirmed``, ``start_qr_login``) and render the code
in their own UI instead of routing through a hosted page.
"""

from __future__ import annotations

import json

from music_assistant_models.errors import InvalidDataError, LoginFailed

from ya_passport_auth import Credentials, PassportClient
from ya_passport_auth.exceptions import YaPassportError

from .errors import raise_mapped

__all__ = ["login_with_cookies", "require_music_token"]


def require_music_token(creds: Credentials, *, flow: str) -> str:
    """Return the music token from *creds* or raise a uniform error.

    Args:
        creds: Credentials returned by a completed login flow.
        flow: Flow name for the error message (e.g. ``"Device"``).

    Raises:
        LoginFailed: The flow succeeded but Passport returned no music token.
    """
    music_token = creds.music_token
    if music_token is None:
        raise LoginFailed(f"{flow} auth succeeded but no music token was returned")
    return music_token.get_secret()


async def login_with_cookies(cookies_input: str) -> Credentials:
    """Authenticate using browser cookies exported from passport.yandex.ru.

    Supports two input formats: the JSON array produced by "Copy Cookies"
    browser extensions (``[{"name": ..., "value": ...}, ...]``) and a raw
    cookie string (``"key1=value1; key2=value2"``).

    Args:
        cookies_input: The pasted cookies in either format.

    Returns:
        The credentials derived from the cookie session.

    Raises:
        InvalidDataError: The input is empty or malformed.
        LoginFailed: Passport rejected the cookies.
        ResourceTemporarilyUnavailable: Transient Passport failure.
    """
    cookies_input = cookies_input.strip()
    if not cookies_input:
        raise InvalidDataError("Empty cookies string")

    cookies = cookies_input
    if cookies_input.startswith("["):
        try:
            raw = json.loads(cookies_input)
        except json.JSONDecodeError as err:
            raise InvalidDataError("Invalid JSON in cookies") from err
        if not isinstance(raw, list):
            raise InvalidDataError(
                "Invalid JSON cookies format. Expected an array of cookie objects."
            )
        validated: list[str] = []
        for idx, item in enumerate(raw):
            if not isinstance(item, dict):
                raise InvalidDataError(
                    f"Invalid JSON cookies format. Cookie at index {idx} must be an object."
                )
            if "name" not in item or "value" not in item:
                raise InvalidDataError(
                    f"Invalid JSON cookies format. Cookie at index {idx} must contain "
                    "'name' and 'value'."
                )
            validated.append(f"{item['name']}={item['value']}")
        cookies = "; ".join(validated)

    if "=" not in cookies:
        raise InvalidDataError("Invalid cookie format. Expected 'key=value; ...' or JSON array.")

    try:
        async with PassportClient.create() as client:
            return await client.login_cookies(cookies)
    except YaPassportError as err:
        raise_mapped(err, context="Cookie authentication")
