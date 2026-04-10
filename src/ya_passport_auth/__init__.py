"""ya-passport-auth — async Yandex Passport (mobile) auth library.

Public API is populated incrementally in later tasks. Phase 0 ships only
the package marker and version.
"""

from ya_passport_auth._version import __version__
from ya_passport_auth.config import ClientConfig
from ya_passport_auth.credentials import (
    Credentials,
    MemoryCredentialStore,
    SecretStr,
)
from ya_passport_auth.exceptions import (
    AuthFailedError,
    CsrfExtractionError,
    InvalidCredentialsError,
    NetworkError,
    QRPendingError,
    QRTimeoutError,
    RateLimitedError,
    UnexpectedHostError,
    YaPassportError,
)

__all__ = [
    "AuthFailedError",
    "ClientConfig",
    "Credentials",
    "CsrfExtractionError",
    "InvalidCredentialsError",
    "MemoryCredentialStore",
    "NetworkError",
    "QRPendingError",
    "QRTimeoutError",
    "RateLimitedError",
    "SecretStr",
    "UnexpectedHostError",
    "YaPassportError",
    "__version__",
]
