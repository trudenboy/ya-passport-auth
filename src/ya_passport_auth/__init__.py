"""ya-passport-auth — async Yandex Passport (mobile) auth library.

Public API is populated incrementally in later tasks. Phase 0 ships only
the package marker and version.
"""

from ya_passport_auth._version import __version__
from ya_passport_auth.credentials import (
    Credentials,
    MemoryCredentialStore,
    SecretStr,
)

__all__ = [
    "Credentials",
    "MemoryCredentialStore",
    "SecretStr",
    "__version__",
]
