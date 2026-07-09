"""Standard authentication config-entry block for MA yandex providers.

``build_auth_config_entries`` emits the shared block (status label, login
action buttons, "remember session" toggle, hidden token storage, reset
action) and ``handle_auth_action`` implements the matching ACTION dispatch.
Entry labels/descriptions are intentionally NOT set in code — MA localizes
them from the owning provider's ``strings.json``
(``config_entries.<key>.<field>``), with the canonical action keys shared
across providers so the texts can live in the common catalog.

Persisted key names stay provider-specific via :class:`~ya_passport_auth.ma.cascade.KeySpec`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final, cast

from music_assistant_models.config_entries import ConfigEntry
from music_assistant_models.enums import ConfigEntryType
from music_assistant_models.errors import InvalidDataError

from .cascade import KeySpec
from .flow import login_with_cookies, require_music_token, run_device_flow, run_qr_flow

if TYPE_CHECKING:
    from music_assistant_models.config_entries import ConfigValueType

    from .page import DevicePageConfig

__all__ = [
    "ACTION_AUTH_COOKIES",
    "ACTION_AUTH_DEVICE",
    "ACTION_AUTH_QR",
    "ACTION_CLEAR_AUTH",
    "AuthConfigSpec",
    "build_auth_config_entries",
    "handle_auth_action",
    "is_authenticated",
]

# Canonical UI-only action keys. Shared across providers so the button
# labels/descriptions can be authored once in the common strings catalog.
ACTION_AUTH_DEVICE: Final = "auth_device"
ACTION_AUTH_QR: Final = "auth_qr"
ACTION_AUTH_COOKIES: Final = "auth_cookies"
ACTION_CLEAR_AUTH: Final = "clear_auth"


@dataclass(frozen=True, slots=True)
class AuthConfigSpec:
    """Shape of a provider's authentication config block.

    Args:
        keys: The provider's persisted credential key names.
        flows: Enabled login flows — a subset of ``{"device", "qr",
            "cookies"}``.
        remember_visible_after_auth: Whether the "remember session" toggle
            stays visible after login (yandex_station keeps it so users can
            drop long-lived tokens without resetting auth; yandex_music
            hides it).
        cookies_key: Key of the cookies input entry (cookies flow only).
        store_refresh_token: Whether the provider persists a Device Flow
            refresh token (a hidden storage entry is emitted for it).
    """

    keys: KeySpec = field(default_factory=KeySpec)
    flows: frozenset[str] = frozenset({"device", "qr"})
    remember_visible_after_auth: bool = True
    cookies_key: str = "cookies"
    store_refresh_token: bool = True


def is_authenticated(spec: AuthConfigSpec, values: dict[str, ConfigValueType]) -> bool:
    """Return whether *values* carry a usable credential.

    Args:
        spec: The provider's auth config shape.
        values: The config-flow values.
    """
    return bool(values.get(spec.keys.music_token) or values.get(spec.keys.x_token))


async def handle_auth_action(
    mass: object,
    spec: AuthConfigSpec,
    page: DevicePageConfig,
    action: str | None,
    values: dict[str, ConfigValueType],
) -> None:
    """Dispatch an authentication config ACTION, mutating *values* in place.

    Args:
        mass: The MusicAssistant instance.
        spec: The provider's auth config shape.
        page: The provider's device-code page configuration.
        action: The ACTION key MA passed to ``get_config_entries`` (None on
            plain renders).
        values: The config-flow values; tokens are written into the keys
            named by ``spec.keys``.

    Raises:
        InvalidDataError: Missing ``session_id`` / empty cookies input.
        LoginFailed: The selected flow failed terminally.
        ResourceTemporarilyUnavailable: Transient Passport failure.
    """
    keys = spec.keys
    if action == ACTION_AUTH_DEVICE:
        session_id = values.get("session_id")
        if not session_id:
            raise InvalidDataError("Missing session_id for device authentication")
        result = await run_device_flow(mass, str(session_id), page)
        values[keys.music_token] = require_music_token(result.credentials, flow="Device")
        values[keys.x_token] = result.credentials.x_token.get_secret()
        refresh = result.credentials.refresh_token
        values[keys.refresh_token] = refresh.get_secret() if refresh is not None else None

    elif action == ACTION_AUTH_QR:
        session_id = values.get("session_id")
        if not session_id:
            raise InvalidDataError("Missing session_id for QR authentication")
        result = await run_qr_flow(mass, str(session_id))
        values[keys.music_token] = require_music_token(result.credentials, flow="QR")
        values[keys.x_token] = result.credentials.x_token.get_secret()
        values[keys.refresh_token] = None  # QR flow does not yield a refresh_token

    elif action == ACTION_AUTH_COOKIES:
        cookies_val = values.get(spec.cookies_key)
        if not cookies_val:
            raise InvalidDataError("Cookies field is empty")
        creds = await login_with_cookies(str(cookies_val))
        values[keys.music_token] = require_music_token(creds, flow="Cookie")
        values[keys.x_token] = creds.x_token.get_secret()
        values[keys.refresh_token] = None  # cookies flow does not yield a refresh_token
        values[spec.cookies_key] = None  # don't persist raw cookies

    elif action == ACTION_CLEAR_AUTH:
        values[keys.x_token] = None
        values[keys.music_token] = None
        values[keys.refresh_token] = None

    # If the user toggles Remember session off post-auth, drop the long-lived
    # tokens right away so silent refresh can no longer run.
    if values.get(keys.remember_session) is False:
        values[keys.x_token] = None
        values[keys.refresh_token] = None


def build_auth_config_entries(
    spec: AuthConfigSpec,
    values: dict[str, ConfigValueType],
    *,
    status_label: str,
) -> tuple[ConfigEntry, ...]:
    """Build the standard authentication config-entry block.

    Labels/descriptions/action labels come from the owning provider's
    ``strings.json`` (or the common catalog) at serialization — only the
    dynamic status label is passed through in code.

    Args:
        spec: The provider's auth config shape.
        values: The config-flow values (used for hidden token storage and
            authenticated-state visibility).
        status_label: Dynamic status text (provider-supplied, e.g.
            "Authenticated to Yandex.").
    """
    keys = spec.keys
    authed = is_authenticated(spec, values)
    entries: list[ConfigEntry] = [
        ConfigEntry(
            key="label_text",
            type=ConfigEntryType.LABEL,
            label=status_label,
        )
    ]
    if "device" in spec.flows:
        entries.append(
            ConfigEntry(
                key=ACTION_AUTH_DEVICE,
                type=ConfigEntryType.ACTION,
                action=ACTION_AUTH_DEVICE,
                hidden=authed,
            )
        )
    if "qr" in spec.flows:
        entries.append(
            ConfigEntry(
                key=ACTION_AUTH_QR,
                type=ConfigEntryType.ACTION,
                action=ACTION_AUTH_QR,
                hidden=authed,
            )
        )
    entries.append(
        ConfigEntry(
            key=keys.remember_session,
            type=ConfigEntryType.BOOLEAN,
            default_value=True,
            hidden=authed if not spec.remember_visible_after_auth else False,
            advanced=True,
        )
    )
    if "cookies" in spec.flows:
        entries.append(
            ConfigEntry(
                key=spec.cookies_key,
                type=ConfigEntryType.SECURE_STRING,
                required=False,
                hidden=authed,
                advanced=True,
                value="",
            )
        )
        entries.append(
            ConfigEntry(
                key=ACTION_AUTH_COOKIES,
                type=ConfigEntryType.ACTION,
                action=ACTION_AUTH_COOKIES,
                hidden=authed,
                advanced=True,
            )
        )
    entries.append(
        ConfigEntry(
            key=ACTION_CLEAR_AUTH,
            type=ConfigEntryType.ACTION,
            action=ACTION_CLEAR_AUTH,
            hidden=not authed,
        )
    )
    entries.append(
        _hidden_secret(keys.x_token, values, advanced=True),
    )
    entries.append(_hidden_secret(keys.music_token, values))
    if spec.store_refresh_token:
        entries.append(_hidden_secret(keys.refresh_token, values))
    return tuple(entries)


def _hidden_secret(
    key: str, values: dict[str, ConfigValueType], *, advanced: bool = False
) -> ConfigEntry:
    return ConfigEntry(
        key=key,
        type=ConfigEntryType.SECURE_STRING,
        required=False,
        hidden=True,
        advanced=advanced,
        value=cast("str | None", values.get(key)),
    )
