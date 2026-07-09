"""Music Assistant integration layer for the yandex providers.

Shared MA-side plumbing that the five yandex providers (music, station,
ynison, smarthome, alice) previously each carried themselves:

* :mod:`~ya_passport_auth.ma.page` / :mod:`~ya_passport_auth.ma.strings` —
  the localized device-code login page;
* :mod:`~ya_passport_auth.ma.routes` — webserver route lifecycle with
  deferred teardown;
* :mod:`~ya_passport_auth.ma.flow` — blocking device/QR/cookie login flows
  behind MA config actions;
* :mod:`~ya_passport_auth.ma.tokens` — token maintenance with unified MA
  error mapping;
* :mod:`~ya_passport_auth.ma.cascade` — the silent credential-refresh
  cascade, parameterized by provider config keys and hooks;
* :mod:`~ya_passport_auth.ma.config` — the standard auth config-entry block.

Requires the ``ma`` extra (``pip install ya-passport-auth[ma]``). The MA
*server* package is the runtime host and is imported lazily where needed.
"""

from __future__ import annotations

from .cascade import CascadeHooks, CredentialCascade, KeySpec
from .config import (
    ACTION_AUTH_COOKIES,
    ACTION_AUTH_DEVICE,
    ACTION_AUTH_QR,
    ACTION_CLEAR_AUTH,
    AuthConfigSpec,
    build_auth_config_entries,
    handle_auth_action,
    is_authenticated,
)
from .errors import failure_reason, raise_mapped
from .flow import (
    FlowResult,
    login_with_cookies,
    require_music_token,
    run_device_flow,
    run_qr_flow,
)
from .page import DEFAULT_PAGE_STRINGS, DevicePageConfig, build_device_code_page, resolve_language
from .routes import POST_AUTH_GRACE_SECONDS, DeviceCodeRoutes
from .strings import resolve_page_strings, safe_locale
from .tokens import refresh_credentials, refresh_music_token, validate_x_token

__all__ = [
    "ACTION_AUTH_COOKIES",
    "ACTION_AUTH_DEVICE",
    "ACTION_AUTH_QR",
    "ACTION_CLEAR_AUTH",
    "DEFAULT_PAGE_STRINGS",
    "POST_AUTH_GRACE_SECONDS",
    "AuthConfigSpec",
    "CascadeHooks",
    "CredentialCascade",
    "DeviceCodeRoutes",
    "DevicePageConfig",
    "FlowResult",
    "KeySpec",
    "build_auth_config_entries",
    "build_device_code_page",
    "failure_reason",
    "handle_auth_action",
    "is_authenticated",
    "login_with_cookies",
    "raise_mapped",
    "refresh_credentials",
    "refresh_music_token",
    "require_music_token",
    "resolve_language",
    "resolve_page_strings",
    "run_device_flow",
    "run_qr_flow",
    "safe_locale",
    "validate_x_token",
]
