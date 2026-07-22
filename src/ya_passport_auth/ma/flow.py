"""Blocking login flows for Music Assistant config actions.

``run_device_flow``, ``run_oauth_device_flow`` and ``run_qr_flow``
wrap the corresponding library clients with the MA-side plumbing the yandex
providers previously each carried themselves: the hosted device-code page,
the ``AuthenticationHelper`` popup, session-id validation, failure reasons
for the status endpoint, and unified error mapping.

The interactive flows BLOCK until the user confirms or the code expires — MA's
config-flow frontend requires the ACTION handler to return the final values
(hidden ConfigEntry values don't round-trip between successive ACTION
clicks in add-provider mode).
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from music_assistant_models.errors import InvalidDataError, LoginFailed

from ya_passport_auth import Credentials, OAuthDeviceClient, PassportClient, SecretStr
from ya_passport_auth.exceptions import YaPassportError

from .errors import failure_reason, raise_mapped
from .routes import DeviceCodeRoutes
from .strings import resolve_page_strings

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from ya_passport_auth.models import DeviceCodeSession, OAuthTokens

    from .page import DevicePageConfig

_LOGGER = logging.getLogger(__name__)

__all__ = [
    "FlowResult",
    "login_with_cookies",
    "require_music_token",
    "run_device_flow",
    "run_oauth_device_flow",
    "run_qr_flow",
]

# session_id is embedded in a webserver route path — restrict it to a safe
# set so a crafted value can't register overlapping or escape-the-scope routes.
_SAFE_SESSION_ID_RE: Final = re.compile(r"\A[A-Za-z0-9_-]{1,64}\Z")


@dataclass(frozen=True, slots=True)
class FlowResult:
    """Outcome of a completed login flow.

    Args:
        credentials: The full credential set returned by Passport.
        display_login: User-visible Yandex login name when the server
            returned one (for "Logged in as X" banners); empty otherwise.
    """

    credentials: Credentials
    display_login: str


def _require_safe_session_id(session_id: str) -> None:
    if not _SAFE_SESSION_ID_RE.match(session_id):
        raise InvalidDataError("Invalid session_id for authentication")


async def _run_hosted_device_page[DeviceResultT](
    mass: object,
    session_id: str,
    page: DevicePageConfig,
    session: DeviceCodeSession,
    poll_until_confirmed: Callable[[], Awaitable[DeviceResultT]],
) -> DeviceResultT:
    """Present one device-code session through MA and await its result."""
    from music_assistant.helpers.auth import AuthenticationHelper  # noqa: PLC0415

    _LOGGER.info(
        "Device flow started: open %s (expires in %ss)",
        session.verification_url,
        session.expires_in,
    )
    routes = DeviceCodeRoutes(mass, page.domain, session_id)
    routes.register(session, await resolve_page_strings(mass, page))
    try:
        async with AuthenticationHelper(mass, session_id) as auth_helper:
            auth_helper.send_url(routes.page_url)
            try:
                result = await poll_until_confirmed()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                routes.state.update({"state": "failed", "reason": failure_reason(exc)})
                raise
            routes.state["state"] = "done"
            return result
    finally:
        routes.schedule_teardown()


async def run_device_flow(
    mass: object,
    session_id: str,
    page: DevicePageConfig,
    *,
    device_name: str | None = None,
    total_timeout: float | None = None,
) -> FlowResult:
    """Run a complete Yandex Passport Device Flow behind an MA config action.

    Asks Yandex for a device code, presents it on an MA-hosted page (opened
    via the ``AuthenticationHelper`` popup), then polls until the user
    confirms or the code expires. Returns as soon as the outcome is known;
    the page routes stay alive in the background for a grace window so the
    popup can observe the terminal state and close itself.

    Args:
        mass: The MusicAssistant instance.
        session_id: The ``values["session_id"]`` supplied by MA's frontend on
            every ACTION invocation. Validated against a safe character set.
        page: Provider-specific page configuration.
        device_name: Optional device name shown on Yandex's confirmation UI.
        total_timeout: Optional hard cap (seconds) on confirmation polling;
            defaults to the server-provided code lifetime.

    Returns:
        The credentials and display login of the confirmed account.

    Raises:
        InvalidDataError: ``session_id`` is unsafe for a route path.
        LoginFailed: The flow timed out, was denied, or failed terminally.
        ResourceTemporarilyUnavailable: Transient Passport failure.
    """
    _require_safe_session_id(session_id)

    try:
        async with PassportClient.create() as client:
            session = await client.start_device_login(device_name=device_name)
            creds = await _run_hosted_device_page(
                mass,
                session_id,
                page,
                session,
                lambda: client.poll_device_until_confirmed(session, total_timeout=total_timeout),
            )
            _LOGGER.debug("Device flow complete")
            return FlowResult(
                credentials=creds,
                display_login=(creds.display_login or "").strip(),
            )
    except YaPassportError as err:
        raise_mapped(err, context="Device authentication")


async def run_oauth_device_flow(
    mass: object,
    session_id: str,
    page: DevicePageConfig,
    *,
    client_id: str,
    client_secret: str | SecretStr,
    scope: str | None = None,
    device_name: str | None = None,
    total_timeout: float | None = None,
) -> OAuthTokens:
    """Run Device Flow for a provider-owned Yandex OAuth application.

    This reusable MA entry point returns the OAuth token pair unchanged.
    The provider decides how to persist and use it, while this helper owns
    the hosted page, popup, polling, route teardown and MA error mapping.
    """
    _require_safe_session_id(session_id)
    try:
        async with OAuthDeviceClient.create(
            client_id=client_id,
            client_secret=client_secret,
            scope=scope,
        ) as client:
            session = await client.start_device_login(device_name=device_name)
            tokens = await _run_hosted_device_page(
                mass,
                session_id,
                page,
                session,
                lambda: client.poll_device_until_confirmed(session, total_timeout=total_timeout),
            )
            _LOGGER.debug("OAuth device flow complete")
            return tokens
    except YaPassportError as err:
        raise_mapped(err, context="OAuth device authentication")


async def run_qr_flow(mass: object, session_id: str) -> FlowResult:
    """Run a complete QR login flow behind an MA config action.

    Opens the QR code popup via the MA frontend, polls Passport until the
    user scans and confirms in the Yandex app.

    Args:
        mass: The MusicAssistant instance.
        session_id: The ``values["session_id"]`` supplied by MA's frontend.

    Returns:
        The credentials and display login of the confirmed account.

    Raises:
        InvalidDataError: ``session_id`` is unsafe.
        LoginFailed: The flow timed out, was denied, or failed terminally.
        ResourceTemporarilyUnavailable: Transient Passport failure.
    """
    _require_safe_session_id(session_id)
    from music_assistant.helpers.auth import AuthenticationHelper  # noqa: PLC0415

    try:
        async with PassportClient.create() as client:
            qr = await client.start_qr_login()
            async with AuthenticationHelper(mass, session_id) as auth_helper:
                auth_helper.send_url(qr.qr_url)
                creds = await client.poll_qr_until_confirmed(qr)
            _LOGGER.debug("QR flow complete")
            return FlowResult(
                credentials=creds,
                display_login=(creds.display_login or "").strip(),
            )
    except YaPassportError as err:
        raise_mapped(err, context="QR authentication")


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
