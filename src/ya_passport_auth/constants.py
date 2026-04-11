"""Well-known constants for Yandex mobile Passport flows.

The client IDs and secrets below are extracted from the public Yandex
Android apps (Yandex Passport SDK and Yandex Music). They are **not**
confidential — they are compiled into every APK and well-documented
in open-source projects. See ``NOTICE`` for attribution.
"""

from __future__ import annotations

import re
from typing import Final

__all__ = [
    "CSRF_PATTERNS",
    "MUSIC_CLIENT_ID",
    "MUSIC_CLIENT_SECRET",
    "MUSIC_TOKEN_URL",
    "PASSPORT_API_URL",
    "PASSPORT_BFF_URL",
    "PASSPORT_CLIENT_ID",
    "PASSPORT_CLIENT_SECRET",
    "PASSPORT_TOKEN_BY_SESSIONID_URL",
    "PASSPORT_URL",
]

# ------------------------------------------------------------------ #
# OAuth client credentials (public, from Android apps)
# ------------------------------------------------------------------ #
PASSPORT_CLIENT_ID: Final = "c0ebe342af7d48fbbbfcf2d2eedb8f9e"
PASSPORT_CLIENT_SECRET: Final = "ad0a908f0aa341a182a37ecd75bc319e"

MUSIC_CLIENT_ID: Final = "23cabbbdc6cd418abb4b39c32c41195d"
MUSIC_CLIENT_SECRET: Final = "53bc75238f0c4d08a118e51fe9203300"

# ------------------------------------------------------------------ #
# Endpoints
# ------------------------------------------------------------------ #
PASSPORT_URL: Final = "https://passport.yandex.ru"
PASSPORT_API_URL: Final = "https://mobileproxy.passport.yandex.net"
PASSPORT_TOKEN_BY_SESSIONID_URL: Final = f"{PASSPORT_API_URL}/1/bundle/oauth/token_by_sessionid"
MUSIC_TOKEN_URL: Final = "https://oauth.mobile.yandex.net/1/token"

# Passport web BFF — new frontend endpoints replacing the legacy
# ``/registration-validations/`` API. Require ``X-CSRF-Token`` header
# rather than a form field.
PASSPORT_BFF_URL: Final = f"{PASSPORT_URL}/pwl-yandex/api/passport"

# ------------------------------------------------------------------ #
# CSRF extraction patterns (T6 — non-greedy, explicit character classes)
# ------------------------------------------------------------------ #
CSRF_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r'"csrf_token"\s*value="([^"]+)"'),
    re.compile(r"'csrf_token'\s*:\s*'([^']+)'"),
    re.compile(r'"csrf_token"\s*:\s*"([^"]+)"'),
    re.compile(r'window\.__CSRF__\s*=\s*"([^"]+)"'),
)
