"""
Music Assistant helpers for Yandex-backed providers.

The optional ``ma`` extra supplies credential parsing, token maintenance,
silent refresh/rotation, and read-only credential sharing between providers.
Interactive QR and Device Flow presentation stays in each provider, using the
public :class:`ya_passport_auth.PassportClient` login primitives directly.
"""

from __future__ import annotations

from .borrow import (
    BORROW_SOURCE_OWN,
    BorrowedCredentialSource,
    list_yandex_music_instances,
)
from .cascade import CascadeHooks, CredentialCascade, KeySpec
from .errors import raise_mapped
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
    "refresh_credentials",
    "refresh_music_token",
    "refresh_oauth_tokens",
    "require_music_token",
    "validate_x_token",
]
