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
    AuthFailedError,
    CredentialSourceUnavailableError,
    CsrfExtractionError,
    DeviceCodeTimeoutError,
    InvalidCredentialsError,
    LoginTimeoutError,
    NetworkError,
    NoUsableCredentialsError,
    QRPendingError,
    QRTimeoutError,
    RateLimitedError,
    UnexpectedHostError,
    YaPassportError,
)
from ya_passport_auth.flows.qr import QrSession
from ya_passport_auth.models import AccountInfo, DeviceCodeSession, OAuthTokens
from ya_passport_auth.oauth import OAuthDeviceClient
from ya_passport_auth.sharing import (
    CredentialReader,
    ResolvedCredentials,
    SharedTokenResolver,
    TokenSnapshot,
)

__all__ = [
    "AccountInfo",
    "AuthFailedError",
    "ClientConfig",
    "CredentialReader",
    "CredentialSourceUnavailableError",
    "Credentials",
    "CsrfExtractionError",
    "DeviceCodeSession",
    "DeviceCodeTimeoutError",
    "InvalidCredentialsError",
    "LoginTimeoutError",
    "MemoryCredentialStore",
    "NetworkError",
    "NoUsableCredentialsError",
    "OAuthDeviceClient",
    "OAuthTokens",
    "PassportClient",
    "QRPendingError",
    "QRTimeoutError",
    "QrSession",
    "RateLimitedError",
    "ResolvedCredentials",
    "SecretStr",
    "SharedTokenResolver",
    "TokenSnapshot",
    "UnexpectedHostError",
    "YaPassportError",
    "__version__",
]
