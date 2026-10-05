"""Read-only credential sharing: one owner rotates, borrowers resolve.

A Yandex account is often used by several consumers at once. Exactly one of
them — the **owner** — persists and rotates the credentials: refresh tokens
are single-use server-side, so a second rotator would burn the owner's token
family. Every other consumer is a **borrower**: it reads the owner's current
tokens through a :class:`CredentialReader` and, when the owner has no usable
music token, mints one in memory from the owner's x_token (a non-rotating
operation).

This module has no framework dependencies. Hosts adapt their own storage by
implementing :class:`CredentialReader` (see :mod:`ya_passport_auth.ma.borrow`
for the Music Assistant adapter).
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Final, Protocol

from ya_passport_auth.client import PassportClient
from ya_passport_auth.credentials import SecretStr
from ya_passport_auth.exceptions import (
    CredentialSourceUnavailableError,
    NoUsableCredentialsError,
)

__all__ = [
    "MUSIC_TOKEN_TTL_S",
    "CredentialReader",
    "CredentialSourceUnavailableError",
    "MintMusicToken",
    "NoUsableCredentialsError",
    "ResolvedCredentials",
    "SharedTokenResolver",
    "TokenSnapshot",
]

# In-memory music-token cache TTL (seconds). Bounds how long a minted token
# is served without re-validating against Passport — after owner-side
# rotation or revocation a borrower converges within one TTL window.
MUSIC_TOKEN_TTL_S: Final = 50 * 60

# Maximum number of distinct x_token entries kept in the music-token cache.
# 4 covers borrow + own simultaneously with one rotation in flight.
_MUSIC_TOKEN_CACHE_MAX: Final = 4

# Maximum number of remembered rejected-token hashes (see invalidate()).
_REJECTED_TOKENS_MAX: Final = 4

MintMusicToken = Callable[[SecretStr], Awaitable[SecretStr]]


@dataclass(frozen=True, slots=True)
class _CachedToken:
    """Music token entry in the in-memory cache."""

    token: SecretStr
    expires_monotonic: float


@dataclass(frozen=True, slots=True)
class TokenSnapshot:
    """One read of the owner's persisted tokens."""

    music_token: SecretStr | None
    x_token: SecretStr | None


@dataclass(frozen=True, slots=True)
class ResolvedCredentials:
    """A usable music token plus the x_token it is consistent with."""

    music_token: SecretStr
    x_token: SecretStr | None


class CredentialReader(Protocol):
    """Read access to the owner's current tokens.

    Implementations raise :class:`CredentialSourceUnavailableError` (or a
    host-specific transient error) when the owner cannot be read yet.
    """

    async def read_tokens(self) -> TokenSnapshot:
        """Return the owner's currently persisted tokens."""
        ...


async def _passport_mint(x_token: SecretStr) -> SecretStr:
    """Exchange *x_token* for a music token through a short-lived client."""
    async with PassportClient.create() as client:
        return await client.refresh_music_token(x_token)


def _hash_token(token: str) -> str:
    """Return the SHA-256 hex digest of a token, used as cache/rejection key.

    Raw tokens are never stored in dict keys (defence-in-depth against
    accidental log / dump leakage of the cache structure).
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class SharedTokenResolver:
    """Resolve usable credentials from an owner without ever writing to it.

    Args:
        reader: Source of the owner's current tokens.
        mint: Exchanges an x_token for a fresh music token. Its exceptions
            propagate unchanged. Defaults to
            :meth:`PassportClient.refresh_music_token` on a short-lived
            client, which raises :class:`YaPassportError` subclasses.
        ttl_s: How long a minted music token is served from memory.
        now: Monotonic-clock seam for tests.
    """

    def __init__(
        self,
        reader: CredentialReader,
        *,
        mint: MintMusicToken | None = None,
        ttl_s: float = MUSIC_TOKEN_TTL_S,
        now: Callable[[], float] = time.monotonic,
    ) -> None:
        self._reader = reader
        self._mint = mint or _passport_mint
        self._ttl_s = ttl_s
        self._now = now
        self._token_cache: dict[str, _CachedToken] = {}
        # Hashes of tokens a consumer reported stale via invalidate(). Blocks
        # the persisted-token fast path until the owner rotates the value —
        # otherwise a 401 on the owner's persisted token would dead-end the
        # borrower on the same stale token. Insertion-ordered, bounded.
        self._rejected_tokens: dict[str, None] = {}
        # Coalesces concurrent mints (401-storm safety).
        self._refresh_lock = asyncio.Lock()

    async def resolve(self) -> ResolvedCredentials:
        """Return a usable music token and the x_token from the same owner read.

        Raises:
            NoUsableCredentialsError: The owner holds no usable credentials.
        """
        snapshot = await self._reader.read_tokens()
        music_token, x_token = snapshot.music_token, snapshot.x_token
        if music_token is not None and (
            _hash_token(music_token.get_secret()) not in self._rejected_tokens
        ):
            return ResolvedCredentials(music_token=music_token, x_token=x_token)
        if x_token is None:
            if music_token is not None:
                raise NoUsableCredentialsError(
                    "The owner's only music token was rejected and there is no "
                    "x_token to mint a fresh one from",
                    reason="rejected_without_x_token",
                )
            raise NoUsableCredentialsError(
                "The owner holds no credentials", reason="no_credentials"
            )
        minted = await self._mint_cached(x_token.get_secret())
        return ResolvedCredentials(music_token=minted, x_token=x_token)

    async def resolve_music_token(self) -> SecretStr:
        """Return a usable music token (see :meth:`resolve`)."""
        return (await self.resolve()).music_token

    def invalidate(self, token: str | SecretStr) -> None:
        """Mark *token* stale after a 401 — pass whichever token failed.

        Handles all three things a consumer may hold: the owner's x_token
        (drops the minted entry keyed by it), a minted music token (drops
        the matching cache entry by value), and the owner's persisted music
        token (blocks the persisted fast path until the owner rotates the
        value, so the borrower mints from x_token instead of re-serving the
        rejected token forever).

        Args:
            token: The token that Yandex rejected.
        """
        raw = token.get_secret() if isinstance(token, SecretStr) else token
        token_hash = _hash_token(raw)
        self._token_cache.pop(token_hash, None)
        for key, entry in list(self._token_cache.items()):
            if entry.token.get_secret() == raw:
                self._token_cache.pop(key, None)
        self._rejected_tokens.pop(token_hash, None)
        self._rejected_tokens[token_hash] = None
        while len(self._rejected_tokens) > _REJECTED_TOKENS_MAX:
            self._rejected_tokens.pop(next(iter(self._rejected_tokens)))

    async def _mint_cached(self, x_token: str) -> SecretStr:
        cache_key = _hash_token(x_token)
        cached = self._get_fresh(cache_key)
        if cached is not None:
            return cached

        async with self._refresh_lock:
            # Double-check inside the lock — a peer caller may have minted
            # while we were waiting, in which case we reuse their fresh entry
            # instead of issuing a duplicate Passport call.
            cached = self._get_fresh(cache_key)
            if cached is not None:
                return cached
            token = await self._mint(SecretStr(x_token))
            self._store_cached_token(cache_key, token)
            return token

    def _get_fresh(self, cache_key: str) -> SecretStr | None:
        cached = self._token_cache.get(cache_key)
        if cached is None or cached.expires_monotonic <= self._now():
            return None
        # Move-to-end so eviction is LRU: a hit protects the entry.
        self._token_cache.pop(cache_key)
        self._token_cache[cache_key] = cached
        return cached.token

    def _store_cached_token(self, cache_key: str, token: SecretStr) -> None:
        # Pop-then-set positions the (possibly-new) key as most-recent in the
        # insertion-ordered dict; oldest entries are evicted first when full.
        self._token_cache.pop(cache_key, None)
        while len(self._token_cache) >= _MUSIC_TOKEN_CACHE_MAX:
            self._token_cache.pop(next(iter(self._token_cache)))
        self._token_cache[cache_key] = _CachedToken(
            token=token,
            expires_monotonic=self._now() + self._ttl_s,
        )
