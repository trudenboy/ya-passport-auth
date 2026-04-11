"""ya-passport-auth — async Yandex Passport (mobile) auth library."""

try:
    from ya_passport_auth._version import __version__
except ImportError:
    __version__ = "0.0.0"
from ya_passport_auth.client import PassportClient
from ya_passport_auth.config import ClientConfig
from ya_passport_auth.credentials import (
    Credentials,
    MemoryCredentialStore,
    SecretStr,
)
from ya_passport_auth.exceptions import (
    AccountNotFoundError,
    AuthFailedError,
    CaptchaRequiredError,
    CsrfExtractionError,
    InvalidCredentialsError,
    NetworkError,
    PasswordError,
    QRPendingError,
    QRTimeoutError,
    RateLimitedError,
    UnexpectedHostError,
    YaPassportError,
)
from ya_passport_auth.flows.qr import QrSession
from ya_passport_auth.models import AccountInfo, AuthSession, CaptchaChallenge

__all__ = [
    "AccountInfo",
    "AccountNotFoundError",
    "AuthFailedError",
    "AuthSession",
    "CaptchaChallenge",
    "CaptchaRequiredError",
    "ClientConfig",
    "Credentials",
    "CsrfExtractionError",
    "InvalidCredentialsError",
    "MemoryCredentialStore",
    "NetworkError",
    "PassportClient",
    "PasswordError",
    "QRPendingError",
    "QRTimeoutError",
    "QrSession",
    "RateLimitedError",
    "SecretStr",
    "UnexpectedHostError",
    "YaPassportError",
    "__version__",
]
