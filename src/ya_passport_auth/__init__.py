"""ya-passport-auth — async Yandex Passport (mobile) auth library."""

from ya_passport_auth._version import __version__
from ya_passport_auth.client import PassportClient
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
from ya_passport_auth.flows.qr import QrSession
from ya_passport_auth.models import AccountInfo

__all__ = [
    "AccountInfo",
    "AuthFailedError",
    "ClientConfig",
    "Credentials",
    "CsrfExtractionError",
    "InvalidCredentialsError",
    "MemoryCredentialStore",
    "NetworkError",
    "PassportClient",
    "QRPendingError",
    "QRTimeoutError",
    "QrSession",
    "RateLimitedError",
    "SecretStr",
    "UnexpectedHostError",
    "YaPassportError",
    "__version__",
]
