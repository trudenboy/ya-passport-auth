"""Tests for the framework-neutral shared-credentials resolver."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence

import pytest
from aioresponses import aioresponses

import ya_passport_auth
from ya_passport_auth import SecretStr, sharing
from ya_passport_auth.exceptions import AuthFailedError, InvalidCredentialsError, NetworkError
from ya_passport_auth.sharing import (
    MUSIC_TOKEN_TTL_S,
    NoUsableCredentialsError,
    ResolvedCredentials,
    SharedTokenResolver,
    TokenSnapshot,
)


def _s(value: str | None) -> SecretStr | None:
    return SecretStr(value) if value else None


def _snap(music: str | None, x: str | None) -> TokenSnapshot:
    return TokenSnapshot(music_token=_s(music), x_token=_s(x))


class _Reader:
    """Async reader returning queued snapshots; repeats the last one."""

    def __init__(self, snapshots: Sequence[TokenSnapshot]) -> None:
        self._snapshots = list(snapshots)
        self.calls = 0

    async def read_tokens(self) -> TokenSnapshot:
        index = min(self.calls, len(self._snapshots) - 1)
        self.calls += 1
        return self._snapshots[index]


class _MutableReader:
    """Async reader exposing the owner's tokens as mutable attributes."""

    def __init__(self, music: str | None = None, x: str | None = None) -> None:
        self.music = music
        self.x = x

    async def read_tokens(self) -> TokenSnapshot:
        return _snap(self.music, self.x)


class _Mint:
    """Mint double recording which x_token each call received."""

    def __init__(self) -> None:
        self.seen: list[str] = []

    async def __call__(self, x_token: SecretStr) -> SecretStr:
        self.seen.append(x_token.get_secret())
        return SecretStr(f"test-music-minted-{len(self.seen)}")


class _Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def mint() -> _Mint:
    return _Mint()


@pytest.fixture
def clock() -> _Clock:
    return _Clock()


def _resolver(reader: _Reader | _MutableReader, mint: _Mint, clock: _Clock) -> SharedTokenResolver:
    return SharedTokenResolver(reader, mint=mint, now=clock)


class TestResolve:
    async def test_returns_persisted_pair(self, mint: _Mint, clock: _Clock) -> None:
        reader = _Reader([_snap("test-music-1", "test-x-1")])

        creds = await _resolver(reader, mint, clock).resolve()

        assert creds == ResolvedCredentials(
            music_token=SecretStr("test-music-1"), x_token=SecretStr("test-x-1")
        )
        assert mint.seen == []

    async def test_resolve_reads_once(self, mint: _Mint, clock: _Clock) -> None:
        reader = _Reader([_snap(None, "test-x-1")])

        await _resolver(reader, mint, clock).resolve()

        assert reader.calls == 1

    async def test_resolve_mints_from_same_snapshot(self, mint: _Mint, clock: _Clock) -> None:
        reader = _Reader([_snap(None, "test-x-first"), _snap(None, "test-x-second")])

        creds = await _resolver(reader, mint, clock).resolve()

        assert mint.seen == ["test-x-first"]
        assert creds.x_token == SecretStr("test-x-first")
        assert creds.music_token == SecretStr("test-music-minted-1")

    async def test_resolve_music_token_returns_resolved_music(
        self, mint: _Mint, clock: _Clock
    ) -> None:
        reader = _Reader([_snap("test-music-1", "test-x-1")])

        token = await _resolver(reader, mint, clock).resolve_music_token()

        assert token == SecretStr("test-music-1")
        assert reader.calls == 1


class TestNoUsableCredentials:
    async def test_no_tokens(self, mint: _Mint, clock: _Clock) -> None:
        reader = _Reader([_snap(None, None)])

        with pytest.raises(NoUsableCredentialsError) as exc_info:
            await _resolver(reader, mint, clock).resolve()

        assert exc_info.value.reason == "no_credentials"
        assert isinstance(exc_info.value, AuthFailedError)

    async def test_rejected_music_without_x_token(self, mint: _Mint, clock: _Clock) -> None:
        reader = _Reader([_snap("test-music-stale", None)])
        resolver = _resolver(reader, mint, clock)
        resolver.invalidate("test-music-stale")

        with pytest.raises(NoUsableCredentialsError) as exc_info:
            await resolver.resolve()

        assert exc_info.value.reason == "rejected_without_x_token"
        assert mint.seen == []

    async def test_error_messages_contain_no_token_material(
        self, mint: _Mint, clock: _Clock
    ) -> None:
        reader = _Reader([_snap("test-music-secret-0123", None)])
        resolver = _resolver(reader, mint, clock)
        resolver.invalidate("test-music-secret-0123")

        with pytest.raises(NoUsableCredentialsError) as exc_info:
            await resolver.resolve()

        rendered = f"{exc_info.value!s} {exc_info.value!r} {exc_info.value.args!r}"
        assert "test-music-secret-0123" not in rendered


class TestMintCache:
    async def test_mints_from_x_token_and_caches(self, mint: _Mint, clock: _Clock) -> None:
        resolver = _resolver(_MutableReader(x="test-x-1"), mint, clock)

        first = await resolver.resolve_music_token()
        second = await resolver.resolve_music_token()

        assert first == second == SecretStr("test-music-minted-1")
        assert mint.seen == ["test-x-1"]

    async def test_cache_expires_after_ttl(self, mint: _Mint, clock: _Clock) -> None:
        resolver = _resolver(_MutableReader(x="test-x-1"), mint, clock)
        await resolver.resolve_music_token()
        clock.t += MUSIC_TOKEN_TTL_S + 1

        token = await resolver.resolve_music_token()

        assert token == SecretStr("test-music-minted-2")

    async def test_custom_ttl(self, mint: _Mint, clock: _Clock) -> None:
        resolver = SharedTokenResolver(_MutableReader(x="test-x-1"), mint=mint, ttl_s=10, now=clock)
        await resolver.resolve_music_token()
        clock.t += 11

        await resolver.resolve_music_token()

        assert len(mint.seen) == 2

    async def test_invalidate_x_token_forces_mint(self, mint: _Mint, clock: _Clock) -> None:
        resolver = _resolver(_MutableReader(x="test-x-1"), mint, clock)
        await resolver.resolve_music_token()

        resolver.invalidate("test-x-1")
        await resolver.resolve_music_token()

        assert len(mint.seen) == 2

    async def test_invalidate_drops_minted_entry_by_value(self, mint: _Mint, clock: _Clock) -> None:
        resolver = _resolver(_MutableReader(x="test-x-1"), mint, clock)
        minted = await resolver.resolve_music_token()

        resolver.invalidate(minted.get_secret())
        await resolver.resolve_music_token()

        assert len(mint.seen) == 2

    async def test_concurrent_callers_coalesce(self, clock: _Clock) -> None:
        calls: list[str] = []
        release = asyncio.Event()

        async def slow_mint(x_token: SecretStr) -> SecretStr:
            calls.append(x_token.get_secret())
            await release.wait()
            return SecretStr("test-music-minted-slow")

        resolver = SharedTokenResolver(_MutableReader(x="test-x-1"), mint=slow_mint, now=clock)
        tasks = [asyncio.ensure_future(resolver.resolve_music_token()) for _ in range(5)]
        await asyncio.sleep(0)
        release.set()
        tokens = await asyncio.gather(*tasks)

        assert calls == ["test-x-1"]
        assert set(tokens) == {SecretStr("test-music-minted-slow")}

    async def test_eviction_drops_oldest_beyond_four(self, mint: _Mint, clock: _Clock) -> None:
        reader = _MutableReader()
        resolver = _resolver(reader, mint, clock)
        for i in range(5):
            reader.x = f"test-x-{i}"
            await resolver.resolve_music_token()
        for i in range(1, 5):
            reader.x = f"test-x-{i}"
            await resolver.resolve_music_token()
        assert len(mint.seen) == 5

        reader.x = "test-x-0"
        await resolver.resolve_music_token()

        assert mint.seen.count("test-x-0") == 2

    async def test_cache_hit_refreshes_lru_position(self, mint: _Mint, clock: _Clock) -> None:
        reader = _MutableReader()
        resolver = _resolver(reader, mint, clock)
        for i in range(4):
            reader.x = f"test-x-{i}"
            await resolver.resolve_music_token()
        reader.x = "test-x-0"
        await resolver.resolve_music_token()
        reader.x = "test-x-4"
        await resolver.resolve_music_token()

        reader.x = "test-x-0"
        await resolver.resolve_music_token()

        assert mint.seen.count("test-x-0") == 1

    async def test_raw_x_token_never_a_cache_key(self, mint: _Mint, clock: _Clock) -> None:
        resolver = _resolver(_MutableReader(x="test-x-secret-value"), mint, clock)

        await resolver.resolve_music_token()

        assert "test-x-secret-value" not in resolver._token_cache

    async def test_failed_mint_is_not_cached(self, clock: _Clock) -> None:
        calls: list[int] = []

        async def flaky_mint(x_token: SecretStr) -> SecretStr:
            calls.append(1)
            if len(calls) == 1:
                raise NetworkError("blip")
            return SecretStr("test-music-minted-after-retry")

        resolver = SharedTokenResolver(_MutableReader(x="test-x-1"), mint=flaky_mint, now=clock)
        with pytest.raises(NetworkError):
            await resolver.resolve_music_token()

        token = await resolver.resolve_music_token()

        assert token == SecretStr("test-music-minted-after-retry")

    async def test_invalidate_during_inflight_mint(self, clock: _Clock) -> None:
        release = asyncio.Event()

        async def slow_mint(x_token: SecretStr) -> SecretStr:
            await release.wait()
            return SecretStr("test-music-minted-slow")

        resolver = SharedTokenResolver(_MutableReader(x="test-x-1"), mint=slow_mint, now=clock)
        task = asyncio.ensure_future(resolver.resolve_music_token())
        await asyncio.sleep(0)
        resolver.invalidate("test-x-1")
        release.set()

        assert await task == SecretStr("test-music-minted-slow")


class TestRejectedPersistedToken:
    async def test_invalidated_persisted_token_falls_back_to_mint(
        self, mint: _Mint, clock: _Clock
    ) -> None:
        resolver = _resolver(_MutableReader("test-music-stale", "test-x-1"), mint, clock)
        assert await resolver.resolve_music_token() == SecretStr("test-music-stale")

        resolver.invalidate("test-music-stale")
        token = await resolver.resolve_music_token()

        assert token == SecretStr("test-music-minted-1")
        assert mint.seen == ["test-x-1"]

    async def test_owner_rotation_clears_rejection(self, mint: _Mint, clock: _Clock) -> None:
        reader = _MutableReader("test-music-stale", "test-x-1")
        resolver = _resolver(reader, mint, clock)
        resolver.invalidate("test-music-stale")

        reader.music = "test-music-rotated"
        token = await resolver.resolve_music_token()

        assert token == SecretStr("test-music-rotated")
        assert mint.seen == []

    async def test_invalidate_accepts_secretstr(self, mint: _Mint, clock: _Clock) -> None:
        resolver = _resolver(_MutableReader("test-music-stale", "test-x-1"), mint, clock)

        resolver.invalidate(SecretStr("test-music-stale"))

        assert await resolver.resolve_music_token() == SecretStr("test-music-minted-1")

    async def test_rejection_memory_is_bounded(self, mint: _Mint, clock: _Clock) -> None:
        reader = _MutableReader("test-music-0", "test-x-1")
        resolver = _resolver(reader, mint, clock)
        for i in range(5):
            resolver.invalidate(f"test-music-{i}")

        token = await resolver.resolve_music_token()

        assert token == SecretStr("test-music-0")


class TestMintFailures:
    @pytest.mark.parametrize(
        "error", [NetworkError("down"), InvalidCredentialsError("rejected")], ids=repr
    )
    async def test_mint_errors_propagate_unchanged(self, clock: _Clock, error: Exception) -> None:
        async def failing_mint(x_token: SecretStr) -> SecretStr:
            raise error

        resolver = SharedTokenResolver(_MutableReader(x="test-x-1"), mint=failing_mint, now=clock)

        with pytest.raises(type(error)) as exc_info:
            await resolver.resolve()

        assert exc_info.value is error

    async def test_cancellation_propagates_and_releases_lock(self, clock: _Clock) -> None:
        started = asyncio.Event()
        calls: list[int] = []

        async def mint(x_token: SecretStr) -> SecretStr:
            calls.append(1)
            if len(calls) == 1:
                started.set()
                await asyncio.Event().wait()
            return SecretStr("test-music-minted-after-cancel")

        resolver = SharedTokenResolver(_MutableReader(x="test-x-1"), mint=mint, now=clock)
        task = asyncio.ensure_future(resolver.resolve())
        await started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        creds = await asyncio.wait_for(resolver.resolve(), timeout=1)

        assert creds.music_token == SecretStr("test-music-minted-after-cancel")


class TestDefaultMint:
    async def test_mints_through_passport(self, clock: _Clock) -> None:
        reader = _MutableReader(x="test-xtoken-sharing-0123456789")
        resolver = SharedTokenResolver(reader, now=clock)

        with aioresponses() as m:
            m.post(
                "https://oauth.mobile.yandex.net/1/token",
                status=200,
                payload={"access_token": "test-musictoken-sharing-abcdef"},
                headers={"Content-Type": "application/json"},
            )
            creds = await resolver.resolve()

        assert creds.music_token == SecretStr("test-musictoken-sharing-abcdef")


def test_public_exports() -> None:
    for name in (
        "CredentialReader",
        "CredentialSourceUnavailableError",
        "NoUsableCredentialsError",
        "ResolvedCredentials",
        "SharedTokenResolver",
        "TokenSnapshot",
    ):
        assert name in ya_passport_auth.__all__
        assert getattr(ya_passport_auth, name) is getattr(sharing, name)


class TestContainerTypeGuards:
    @pytest.mark.parametrize("field", ["music_token", "x_token"])
    def test_snapshot_rejects_plain_string(self, field: str) -> None:
        kwargs: dict[str, object] = {"music_token": None, "x_token": None}
        kwargs[field] = "test-raw-token-0123456789"

        with pytest.raises(TypeError, match=rf"TokenSnapshot\.{field} must be a SecretStr") as exc:
            TokenSnapshot(**kwargs)  # type: ignore[arg-type]

        assert "test-raw-token-0123456789" not in str(exc.value)

    def test_resolved_rejects_plain_music_token(self) -> None:
        with pytest.raises(
            TypeError, match=r"ResolvedCredentials\.music_token must be a SecretStr"
        ):
            ResolvedCredentials(music_token="test-raw-music", x_token=None)  # type: ignore[arg-type]

    def test_resolved_rejects_missing_music_token(self) -> None:
        with pytest.raises(
            TypeError, match=r"ResolvedCredentials\.music_token must be a SecretStr"
        ):
            ResolvedCredentials(music_token=None, x_token=None)  # type: ignore[arg-type]

    def test_resolved_rejects_plain_x_token(self) -> None:
        with pytest.raises(TypeError, match=r"ResolvedCredentials\.x_token must be a SecretStr"):
            ResolvedCredentials(music_token=SecretStr("test-music"), x_token="test-raw-x")  # type: ignore[arg-type]

    def test_repr_redacts_tokens(self) -> None:
        snapshot = TokenSnapshot(
            music_token=SecretStr("test-music-a"), x_token=SecretStr("test-x-a")
        )
        resolved = ResolvedCredentials(music_token=SecretStr("test-music-b"), x_token=None)

        rendered = repr(snapshot) + repr(resolved)

        assert "test-music-a" not in rendered
        assert "test-x-a" not in rendered
        assert "test-music-b" not in rendered


class TestMintResultValidation:
    async def test_plain_string_mint_result_is_rejected_and_not_cached(self, clock: _Clock) -> None:
        results: list[object] = ["test-raw-minted-0123456789", SecretStr("test-music-minted-ok")]

        async def mint(x_token: SecretStr) -> SecretStr:
            return results.pop(0)  # type: ignore[return-value]

        resolver = SharedTokenResolver(_MutableReader(x="test-x-1"), mint=mint, now=clock)

        with pytest.raises(TypeError, match="mint must return a SecretStr") as exc:
            await resolver.resolve()

        assert "test-raw-minted-0123456789" not in str(exc.value)
        assert "test-raw-minted-0123456789" not in repr(resolver._token_cache)
        creds = await resolver.resolve()
        assert creds.music_token == SecretStr("test-music-minted-ok")


async def test_falsey_mint_callable_is_used_not_replaced(clock: _Clock) -> None:
    class _FalseyMint:
        def __init__(self) -> None:
            self.calls = 0

        def __bool__(self) -> bool:
            return False

        async def __call__(self, x_token: SecretStr) -> SecretStr:
            self.calls += 1
            return SecretStr("test-music-from-falsey-mint")

    falsey_mint = _FalseyMint()
    resolver = SharedTokenResolver(_MutableReader(x="test-x-1"), mint=falsey_mint, now=clock)

    creds = await resolver.resolve()

    assert falsey_mint.calls == 1
    assert creds.music_token == SecretStr("test-music-from-falsey-mint")
