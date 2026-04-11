"""Library-wide configuration for :class:`PassportClient`.

``ClientConfig`` is a frozen dataclass. All network, retry, rate-limit,
and host-allow-list policy flows through it. There is no mutable
runtime override path — every field is immutable after construction so
a misbehaving call site cannot weaken a security invariant for the
whole process.

TLS verification is **always on**. There is no public field, kwarg, or
environment variable to disable it; see the threat model (T3).

The :attr:`pinned_fingerprints` and :attr:`max_retries` fields are
validated at construction time but not yet enforced by the HTTP
client; they are reserved for a future release.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

__all__ = ["DEFAULT_ALLOWED_HOSTS", "DEFAULT_MOBILE_UA", "ClientConfig"]

# Public Yandex mobile client UA — reused from the existing MA provider.
# The string is cosmetic; Yandex does not authenticate on UA.
DEFAULT_MOBILE_UA = "com.yandex.mobile.auth.sdk/7.42.0 (Xiaomi Redmi; Android 10) Yandex"

DEFAULT_ALLOWED_HOSTS: frozenset[str] = frozenset(
    {
        "passport.yandex.ru",
        "www.yandex.ru",
        "mobileproxy.passport.yandex.net",
        "oauth.mobile.yandex.net",
        "oauth.yandex.ru",
        "yandex.ru",
        "quasar.yandex.net",
        "quasar.yandex.ru",
        "iot.quasar.yandex.ru",
    },
)

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


def _ensure_positive(name: str, value: float) -> None:
    if not value > 0:
        raise ValueError(f"ClientConfig.{name} must be > 0, got {value!r}")


@dataclass(frozen=True, slots=True)
class ClientConfig:
    """Immutable configuration for a :class:`PassportClient`."""

    user_agent: str = DEFAULT_MOBILE_UA
    total_timeout_seconds: float = 30.0
    connect_timeout_seconds: float = 10.0
    min_request_interval_seconds: float = 0.2
    max_retries: int = 2  # reserved for future retry policy
    qr_poll_interval_seconds: float = 2.0
    qr_poll_total_timeout_seconds: float = 120.0
    allowed_hosts: frozenset[str] = field(default=DEFAULT_ALLOWED_HOSTS)
    pinned_fingerprints: frozenset[str] | None = None  # reserved for future SPKI pinning

    def __post_init__(self) -> None:
        if not self.user_agent:
            raise ValueError("ClientConfig.user_agent must not be empty")

        _ensure_positive("total_timeout_seconds", self.total_timeout_seconds)
        _ensure_positive("connect_timeout_seconds", self.connect_timeout_seconds)
        _ensure_positive("min_request_interval_seconds", self.min_request_interval_seconds)
        _ensure_positive("qr_poll_interval_seconds", self.qr_poll_interval_seconds)
        _ensure_positive("qr_poll_total_timeout_seconds", self.qr_poll_total_timeout_seconds)

        if self.max_retries < 0:
            raise ValueError(
                f"ClientConfig.max_retries must be >= 0, got {self.max_retries!r}",
            )

        if self.connect_timeout_seconds > self.total_timeout_seconds:
            raise ValueError(
                "ClientConfig.connect_timeout_seconds must be <= total_timeout_seconds",
            )

        if self.qr_poll_interval_seconds > self.qr_poll_total_timeout_seconds:
            raise ValueError(
                "ClientConfig.qr_poll_interval_seconds must be <= qr_poll_total_timeout_seconds",
            )

        if not self.allowed_hosts:
            raise ValueError("ClientConfig.allowed_hosts must not be empty")

        if self.pinned_fingerprints is not None:
            if not self.pinned_fingerprints:
                raise ValueError(
                    "ClientConfig.pinned_fingerprints must be None or a "
                    "non-empty frozenset — pass None to opt out",
                )
            for fp in self.pinned_fingerprints:
                if not _SHA256_HEX.match(fp):
                    raise ValueError(
                        f"ClientConfig.pinned_fingerprints entry {fp!r} is "
                        f"not a lowercase hex SHA-256 fingerprint",
                    )
