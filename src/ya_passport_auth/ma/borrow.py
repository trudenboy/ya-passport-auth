"""Borrowed credentials: one Yandex account shared across MA providers.

Extracted from the ``yandex_ynison`` plugin's borrow mode (its spec 0004).
A provider links to a configured ``yandex_music`` instance and *borrows* its
tokens instead of running its own login:

* the **owner** (the yandex_music instance) is the only party that persists
  and rotates credentials — refresh tokens are single-use server-side, so a
  second rotator would burn the owner's token family;
* borrowers only *read* the owner's config and, when the owner has not
  refreshed a music token yet, mint one in memory from the owner's x_token —
  a non-rotating operation — with a TTL cache so concurrent consumers and
  401 storms coalesce into a single Passport call.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, cast

from music_assistant_models.enums import ProviderType
from music_assistant_models.errors import LoginFailed

from ya_passport_auth import SecretStr

from .tokens import refresh_music_token

if TYPE_CHECKING:
    from types import MappingProxyType

__all__ = [
    "BORROW_SOURCE_OWN",
    "BorrowedCredentialSource",
    "list_yandex_music_instances",
]

# Sentinel config value for "use this provider's own login" in the account
# source dropdown (matches the value the yandex_ynison plugin established).
BORROW_SOURCE_OWN: Final = "__own__"

# In-memory music-token cache TTL (seconds). Yandex music tokens live ~60 min;
# 50 min leaves 10 min headroom before the server would reject them.
MUSIC_TOKEN_TTL_S: Final = 50 * 60

# Maximum number of distinct x_token entries kept in the music-token cache.
# 4 covers borrow + own simultaneously with one rotation in flight.
_MUSIC_TOKEN_CACHE_MAX: Final = 4


def list_yandex_music_instances(mass: object) -> list[tuple[str, str]]:
    """List configured yandex_music provider instances.

    Args:
        mass: The MusicAssistant instance (reads ``config.get("providers")``).

    Returns:
        ``(instance_id, display_name)`` pairs for the account-source dropdown.
    """
    instances: list[tuple[str, str]] = []
    config = getattr(mass, "config", None)
    get = getattr(config, "get", None)
    if not callable(get):
        return instances
    raw_providers = cast("MappingProxyType[str, object]", get("providers", {}))
    for instance_id, prov_conf in raw_providers.items():
        if not isinstance(prov_conf, dict) or prov_conf.get("domain") != "yandex_music":
            continue
        display_name = prov_conf.get("name") or instance_id
        instances.append((str(instance_id), str(display_name)))
    return instances


@dataclass(frozen=True, slots=True)
class _CachedToken:
    """Music token entry in the in-memory cache."""

    token: SecretStr
    expires_monotonic: float


def _hash_x_token(x_token: str) -> str:
    """Return the SHA-256 hex digest of an x_token, used as cache key.

    The raw x_token is never stored in dict keys (defence-in-depth against
    accidental log / dump leakage of the cache structure).
    """
    return hashlib.sha256(x_token.encode("utf-8")).hexdigest()


class BorrowedCredentialSource:
    """Read-only view of a linked yandex_music instance's credentials.

    Args:
        mass: The MusicAssistant instance.
        instance_id: The linked yandex_music provider instance id.
        music_token_key: The owner's config key for the music-scoped token
            (yandex_music persists it as ``"token"``).
        x_token_key: The owner's config key for the long-lived x_token.
        now: Monotonic-clock seam for tests.
    """

    def __init__(
        self,
        mass: object,
        instance_id: str,
        *,
        music_token_key: str = "token",  # noqa: S107 — config KEY name, not a secret
        x_token_key: str = "x_token",  # noqa: S107
        now: Callable[[], float] = time.monotonic,
    ) -> None:
        self._mass = mass
        self.instance_id = instance_id
        self._music_token_key = music_token_key
        self._x_token_key = x_token_key
        self._now = now
        self._token_cache: dict[str, _CachedToken] = {}
        # Coalesces concurrent in-memory refreshes (401-storm safety).
        self._refresh_lock = asyncio.Lock()

    def read_tokens(self) -> tuple[str | None, str | None]:
        """Read ``(music_token, x_token)`` from the owner's config.

        Raises:
            LoginFailed: The linked instance is not loaded, or the configured
                id points at something that is not a yandex_music music
                provider — distinct messages so operators can tell the
                "not loaded" and "unauthenticated" states apart.
        """
        get_provider = getattr(self._mass, "get_provider", None)
        owner = get_provider(self.instance_id) if callable(get_provider) else None
        if owner is None:
            raise LoginFailed(
                f"Linked Yandex Music instance '{self.instance_id}' is not loaded. "
                "Check that the Yandex Music provider is enabled and configured."
            )
        # Guard against a stale/manually-edited instance id pointing at a
        # non-YM provider — otherwise reading unrelated config keys yields a
        # misleading "no credentials" error further down.
        domain = getattr(owner, "domain", None)
        provider_type = getattr(owner, "type", None)
        if domain != "yandex_music" or provider_type != ProviderType.MUSIC:
            raise LoginFailed(
                f"Linked provider instance '{self.instance_id}' is not a Yandex Music "
                f"music provider (domain={domain!r}, type={provider_type!r}). "
                "Re-select the Yandex Music source in this provider's configuration."
            )
        config = getattr(owner, "config", None)
        get_value = getattr(config, "get_value", None)
        if not callable(get_value):
            raise LoginFailed(
                f"Linked Yandex Music instance '{self.instance_id}' has no readable config."
            )
        music_token = get_value(self._music_token_key)
        x_token = get_value(self._x_token_key)
        return (
            str(music_token) if music_token else None,
            str(x_token) if x_token else None,
        )

    async def resolve_music_token(self) -> SecretStr:
        """Return a usable music token without writing to the owner's config.

        Prefers the owner's persisted music token; when only an x_token is
        stored (the owner hasn't refreshed yet), mints a music token in
        memory — cached per x_token for :data:`MUSIC_TOKEN_TTL_S` so
        concurrent consumers coalesce into one Passport call. The owner
        stays the single writer of persisted credentials.

        Raises:
            LoginFailed: The owner is unavailable, holds no credentials, or
                Yandex explicitly rejected the x_token.
            ResourceTemporarilyUnavailable: Transient Passport failure.
        """
        music_token, x_token = self.read_tokens()
        if music_token:
            return SecretStr(music_token)
        if not x_token:
            raise LoginFailed(
                f"Linked Yandex Music instance '{self.instance_id}' has no credentials. "
                "Authenticate the Yandex Music provider (and enable Remember session) first."
            )
        return await self._refresh_via_x_token(x_token)

    def invalidate(self, x_token: str) -> None:
        """Drop the cache entry for an x_token (e.g. after a 401).

        Args:
            x_token: The owner x_token whose minted music token proved stale.
        """
        self._token_cache.pop(_hash_x_token(x_token), None)

    async def _refresh_via_x_token(self, x_token: str) -> SecretStr:
        cache_key = _hash_x_token(x_token)
        cached = self._token_cache.get(cache_key)
        if cached is not None and cached.expires_monotonic > self._now():
            return cached.token

        async with self._refresh_lock:
            # Double-check inside the lock — a peer caller may have refreshed
            # while we were waiting, in which case we reuse their fresh entry
            # instead of issuing a duplicate Passport call.
            cached = self._token_cache.get(cache_key)
            if cached is not None and cached.expires_monotonic > self._now():
                return cached.token
            token = await refresh_music_token(SecretStr(x_token))
            self._store_cached_token(cache_key, token)
            return token

    def _store_cached_token(self, cache_key: str, token: SecretStr) -> None:
        # Reordering: pop-then-set positions the (possibly-new) key as
        # most-recent in Python's insertion-ordered dict; oldest entries are
        # evicted first when the cache is full.
        self._token_cache.pop(cache_key, None)
        while len(self._token_cache) >= _MUSIC_TOKEN_CACHE_MAX:
            oldest = next(iter(self._token_cache))
            self._token_cache.pop(oldest)
        self._token_cache[cache_key] = _CachedToken(
            token=token,
            expires_monotonic=self._now() + MUSIC_TOKEN_TTL_S,
        )
