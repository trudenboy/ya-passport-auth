"""Music Assistant integration layer for the yandex providers.

Shared MA-side plumbing for Yandex-backed providers:

* :mod:`~ya_passport_auth.ma.flow` — cookie login behind MA config actions;
* :mod:`~ya_passport_auth.ma.tokens` — token maintenance with unified MA
  error mapping;
* :mod:`~ya_passport_auth.ma.cascade` — the silent credential-refresh
  cascade, parameterized by provider config keys and hooks;
* :mod:`~ya_passport_auth.ma.borrow` — borrowed-credentials source for
  sharing one Yandex account across providers.

Requires the ``ma`` extra (``pip install ya-passport-auth[ma]``). Only
``music_assistant_models`` is a runtime dependency — the MA *server* package
itself is never imported. Interactive device/QR login is not covered here —
MA's setup flows drive :class:`~ya_passport_auth.PassportClient` directly.
"""

from __future__ import annotations

from .borrow import (
    BORROW_SOURCE_OWN,
    BorrowedCredentialSource,
    list_yandex_music_instances,
)
from .cascade import CascadeHooks, CredentialCascade, KeySpec
from .errors import raise_mapped, raise_mapped_refresh
from .flow import login_with_cookies, require_music_token
from .tokens import refresh_credentials, refresh_music_token, refresh_oauth_tokens, validate_x_token

__all__ = [
    "BORROW_SOURCE_OWN",
    "BorrowedCredentialSource",
    "CascadeHooks",
    "CredentialCascade",
    "KeySpec",
    "list_yandex_music_instances",
    "login_with_cookies",
    "raise_mapped",
    "raise_mapped_refresh",
    "refresh_credentials",
    "refresh_music_token",
    "refresh_oauth_tokens",
    "require_music_token",
    "validate_x_token",
]
