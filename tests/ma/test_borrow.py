"""Tests for the borrowed-credentials source (shared Yandex account)."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest
from music_assistant_models.enums import ProviderType
from music_assistant_models.errors import LoginFailed, ResourceTemporarilyUnavailable

from ya_passport_auth import SecretStr
from ya_passport_auth.ma import borrow as borrow_mod
from ya_passport_auth.ma.borrow import (
    MUSIC_TOKEN_TTL_S,
    BorrowedCredentialSource,
    list_yandex_music_instances,
)

if TYPE_CHECKING:
    from collections.abc import Callable


class _OwnerConfig:
    def __init__(self, values: dict[str, object]) -> None:
        self._values = values

    def get_value(self, key: str) -> object:
        return self._values.get(key)


class _Owner:
    def __init__(
        self,
        values: dict[str, object],
        *,
        domain: str = "yandex_music",
        provider_type: ProviderType = ProviderType.MUSIC,
    ) -> None:
        self.domain = domain
        self.type = provider_type
        self.config = _OwnerConfig(values)


class _Mass:
    def __init__(self, providers: dict[str, object] | None = None) -> None:
        self._providers = providers or {}

    def get_provider(self, instance_id: str) -> object | None:
        return self._providers.get(instance_id)


class _Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def clock() -> _Clock:
    return _Clock()


def _source(
    mass: _Mass, clock: Callable[[], float], instance_id: str = "ym-1"
) -> BorrowedCredentialSource:
    return BorrowedCredentialSource(mass, instance_id, now=clock)


@pytest.fixture
def passport_calls(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    async def fake_refresh(x_token: SecretStr) -> SecretStr:
        calls.append(x_token.get_secret())
        return SecretStr(f"test-music-minted-{len(calls)}")

    monkeypatch.setattr(borrow_mod, "refresh_music_token", fake_refresh)
    return calls


def _secrets(pair: tuple[object, object]) -> tuple[str | None, str | None]:
    music, x = pair
    return (
        music.get_secret() if isinstance(music, SecretStr) else None,
        x.get_secret() if isinstance(x, SecretStr) else None,
    )


class TestReadTokens:
    def test_reads_owner_tokens(self, clock: _Clock) -> None:
        mass = _Mass({"ym-1": _Owner({"token": "test-music-1", "x_token": "test-x-1"})})
        assert _secrets(_source(mass, clock).read_tokens()) == ("test-music-1", "test-x-1")

    def test_returns_secretstr_not_raw(self, clock: _Clock) -> None:
        # Library discipline: tokens cross API boundaries wrapped, never raw.
        mass = _Mass({"ym-1": _Owner({"token": "test-music-1", "x_token": "test-x-1"})})
        music, x = _source(mass, clock).read_tokens()
        assert isinstance(music, SecretStr)
        assert isinstance(x, SecretStr)
        assert "test-music-1" not in repr((music, x))

    def test_unwraps_secretstr_config_values(self, clock: _Clock) -> None:
        # An owner storing SecretStr must not be corrupted into "**********".
        mass = _Mass(
            {"ym-1": _Owner({"token": SecretStr("test-music-1"), "x_token": SecretStr("test-x-1")})}
        )
        assert _secrets(_source(mass, clock).read_tokens()) == ("test-music-1", "test-x-1")

    def test_owner_not_loaded_is_transient(self, clock: _Clock) -> None:
        # Startup load-ordering: the owner may simply not be up yet — the
        # borrower must retry later, not flip into a terminal auth failure.
        with pytest.raises(ResourceTemporarilyUnavailable, match="is not loaded"):
            _source(_Mass(), clock).read_tokens()

    def test_wrong_domain_guard(self, clock: _Clock) -> None:
        mass = _Mass({"ym-1": _Owner({}, domain="spotify")})
        with pytest.raises(LoginFailed, match="not a Yandex Music"):
            _source(mass, clock).read_tokens()

    def test_wrong_type_guard(self, clock: _Clock) -> None:
        mass = _Mass({"ym-1": _Owner({}, provider_type=ProviderType.PLAYER)})
        with pytest.raises(LoginFailed, match="not a Yandex Music"):
            _source(mass, clock).read_tokens()

    def test_custom_key_names(self, clock: _Clock) -> None:
        mass = _Mass({"ym-1": _Owner({"music_token": "test-music-1", "xt": "test-x-1"})})
        source = BorrowedCredentialSource(
            mass,
            "ym-1",
            music_token_key="music_token",
            x_token_key="xt",
            now=clock,
        )
        assert _secrets(source.read_tokens()) == ("test-music-1", "test-x-1")


class TestResolveMusicToken:
    async def test_prefers_persisted_token(self, clock: _Clock, passport_calls: list[str]) -> None:
        mass = _Mass({"ym-1": _Owner({"token": "test-music-1", "x_token": "test-x-1"})})
        token = await _source(mass, clock).resolve_music_token()
        assert token.get_secret() == "test-music-1"
        assert passport_calls == []  # never hits Passport when the owner has a token

    async def test_no_credentials(self, clock: _Clock, passport_calls: list[str]) -> None:
        mass = _Mass({"ym-1": _Owner({})})
        with pytest.raises(LoginFailed, match="has no credentials"):
            await _source(mass, clock).resolve_music_token()

    async def test_mints_from_x_token_and_caches(
        self, clock: _Clock, passport_calls: list[str]
    ) -> None:
        mass = _Mass({"ym-1": _Owner({"x_token": "test-x-1"})})
        source = _source(mass, clock)
        first = await source.resolve_music_token()
        second = await source.resolve_music_token()
        assert first.get_secret() == second.get_secret() == "test-music-minted-1"
        assert passport_calls == ["test-x-1"]  # second call served from cache

    async def test_cache_expires_after_ttl(self, clock: _Clock, passport_calls: list[str]) -> None:
        mass = _Mass({"ym-1": _Owner({"x_token": "test-x-1"})})
        source = _source(mass, clock)
        await source.resolve_music_token()
        clock.t += MUSIC_TOKEN_TTL_S + 1
        token = await source.resolve_music_token()
        assert token.get_secret() == "test-music-minted-2"
        assert len(passport_calls) == 2

    async def test_invalidate_forces_refresh(
        self, clock: _Clock, passport_calls: list[str]
    ) -> None:
        mass = _Mass({"ym-1": _Owner({"x_token": "test-x-1"})})
        source = _source(mass, clock)
        await source.resolve_music_token()
        source.invalidate("test-x-1")
        await source.resolve_music_token()
        assert len(passport_calls) == 2

    async def test_concurrent_callers_coalesce(
        self, clock: _Clock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A 401 storm must trigger exactly one Passport call.
        calls: list[str] = []
        release = asyncio.Event()

        async def slow_refresh(x_token: SecretStr) -> SecretStr:
            calls.append(x_token.get_secret())
            await release.wait()
            return SecretStr("test-music-minted-slow")

        monkeypatch.setattr(borrow_mod, "refresh_music_token", slow_refresh)
        mass = _Mass({"ym-1": _Owner({"x_token": "test-x-1"})})
        source = _source(mass, clock)

        tasks = [asyncio.ensure_future(source.resolve_music_token()) for _ in range(5)]
        await asyncio.sleep(0)  # let all tasks reach the lock
        release.set()
        tokens = await asyncio.gather(*tasks)
        assert len(calls) == 1
        assert {t.get_secret() for t in tokens} == {"test-music-minted-slow"}

    async def test_cache_eviction_keeps_bound(
        self, clock: _Clock, passport_calls: list[str]
    ) -> None:
        owner = _Owner({"x_token": "test-x-0"})
        mass = _Mass({"ym-1": owner})
        source = _source(mass, clock)
        for i in range(6):
            owner.config._values["x_token"] = f"test-x-{i}"
            await source.resolve_music_token()
        assert len(source._token_cache) <= 4
        # The oldest entry was evicted — resolving it again hits Passport.
        owner.config._values["x_token"] = "test-x-0"
        await source.resolve_music_token()
        assert passport_calls.count("test-x-0") == 2

    async def test_raw_x_token_never_a_cache_key(
        self, clock: _Clock, passport_calls: list[str]
    ) -> None:
        mass = _Mass({"ym-1": _Owner({"x_token": "test-x-secret-value"})})
        source = _source(mass, clock)
        await source.resolve_music_token()
        assert "test-x-secret-value" not in source._token_cache

    async def test_failed_mint_does_not_poison_cache(
        self, clock: _Clock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A transient Passport failure must not be cached — the next resolve
        # retries instead of serving the failure or a stale entry.
        calls: list[int] = []

        async def flaky_refresh(x_token: SecretStr) -> SecretStr:
            calls.append(1)
            if len(calls) == 1:
                raise ResourceTemporarilyUnavailable("blip")
            return SecretStr("test-music-minted-after-retry")

        monkeypatch.setattr(borrow_mod, "refresh_music_token", flaky_refresh)
        mass = _Mass({"ym-1": _Owner({"x_token": "test-x-1"})})
        source = _source(mass, clock)
        with pytest.raises(ResourceTemporarilyUnavailable):
            await source.resolve_music_token()
        token = await source.resolve_music_token()
        assert token.get_secret() == "test-music-minted-after-retry"
        assert len(calls) == 2

    async def test_eviction_keeps_recent_survivors(
        self, clock: _Clock, passport_calls: list[str]
    ) -> None:
        owner = _Owner({"x_token": "test-x-0"})
        mass = _Mass({"ym-1": owner})
        source = _source(mass, clock)
        for i in range(5):  # x-0..x-4; cap is 4, so x-0 is evicted
            owner.config._values["x_token"] = f"test-x-{i}"
            await source.resolve_music_token()
        # Survivors x-1..x-4 are still served from cache — no new mints.
        for i in range(1, 5):
            owner.config._values["x_token"] = f"test-x-{i}"
            await source.resolve_music_token()
        assert len(passport_calls) == 5

    async def test_cache_hit_refreshes_lru_position(
        self, clock: _Clock, passport_calls: list[str]
    ) -> None:
        # LRU, not FIFO: a hit protects the entry from the next eviction.
        owner = _Owner({"x_token": "test-x-0"})
        mass = _Mass({"ym-1": owner})
        source = _source(mass, clock)
        for i in range(4):  # fill the cache: x-0..x-3
            owner.config._values["x_token"] = f"test-x-{i}"
            await source.resolve_music_token()
        owner.config._values["x_token"] = "test-x-0"
        await source.resolve_music_token()  # hit — bumps x-0 to most recent
        owner.config._values["x_token"] = "test-x-4"
        await source.resolve_music_token()  # evicts x-1 (oldest), not x-0
        owner.config._values["x_token"] = "test-x-0"
        await source.resolve_music_token()
        assert passport_calls.count("test-x-0") == 1  # still cached

    async def test_invalidate_during_inflight_refresh(
        self, clock: _Clock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # invalidate() racing an in-flight mint must not resurrect a stale
        # entry or crash; the freshly minted token is stored afterwards.
        release = asyncio.Event()

        async def slow_refresh(x_token: SecretStr) -> SecretStr:
            await release.wait()
            return SecretStr("test-music-minted-slow")

        monkeypatch.setattr(borrow_mod, "refresh_music_token", slow_refresh)
        mass = _Mass({"ym-1": _Owner({"x_token": "test-x-1"})})
        source = _source(mass, clock)
        task = asyncio.ensure_future(source.resolve_music_token())
        await asyncio.sleep(0)
        source.invalidate("test-x-1")
        release.set()
        token = await task
        assert token.get_secret() == "test-music-minted-slow"


class TestRejectedPersistedToken:
    async def test_invalidated_persisted_token_falls_back_to_mint(
        self, clock: _Clock, passport_calls: list[str]
    ) -> None:
        # A 401 on the owner's PERSISTED music token must not dead-end the
        # borrower: after invalidate(), resolve mints from x_token instead of
        # re-serving the rejected value until the owner rotates it.
        mass = _Mass({"ym-1": _Owner({"token": "test-music-stale", "x_token": "test-x-1"})})
        source = _source(mass, clock)
        assert (await source.resolve_music_token()).get_secret() == "test-music-stale"
        source.invalidate("test-music-stale")
        token = await source.resolve_music_token()
        assert token.get_secret() == "test-music-minted-1"
        assert passport_calls == ["test-x-1"]

    async def test_owner_rotation_clears_rejection(
        self, clock: _Clock, passport_calls: list[str]
    ) -> None:
        # Once the owner persists a NEW music token, it is trusted again.
        owner = _Owner({"token": "test-music-stale", "x_token": "test-x-1"})
        mass = _Mass({"ym-1": owner})
        source = _source(mass, clock)
        source.invalidate("test-music-stale")
        owner.config._values["token"] = "test-music-rotated"
        token = await source.resolve_music_token()
        assert token.get_secret() == "test-music-rotated"
        assert passport_calls == []

    async def test_invalidate_accepts_secretstr(
        self, clock: _Clock, passport_calls: list[str]
    ) -> None:
        mass = _Mass({"ym-1": _Owner({"token": "test-music-stale", "x_token": "test-x-1"})})
        source = _source(mass, clock)
        source.invalidate(SecretStr("test-music-stale"))
        token = await source.resolve_music_token()
        assert token.get_secret() == "test-music-minted-1"

    async def test_rejected_persisted_without_x_token_is_terminal(
        self, clock: _Clock, passport_calls: list[str]
    ) -> None:
        mass = _Mass({"ym-1": _Owner({"token": "test-music-stale"})})
        source = _source(mass, clock)
        source.invalidate("test-music-stale")
        with pytest.raises(LoginFailed, match="rejected"):
            await source.resolve_music_token()

    async def test_invalidate_drops_minted_entry_by_value(
        self, clock: _Clock, passport_calls: list[str]
    ) -> None:
        # The consumer only holds the MUSIC token it got 401 with — passing
        # it (not the x_token) must still drop the matching mint-cache entry.
        mass = _Mass({"ym-1": _Owner({"x_token": "test-x-1"})})
        source = _source(mass, clock)
        minted = await source.resolve_music_token()
        source.invalidate(minted.get_secret())
        await source.resolve_music_token()
        assert len(passport_calls) == 2


class TestListInstances:
    def test_lists_only_yandex_music(self) -> None:
        class _Config:
            @staticmethod
            def get(key: str, default: object = None) -> object:
                return {
                    "ym-a": {"domain": "yandex_music", "name": "Main"},
                    "ym-b": {"domain": "yandex_music"},
                    "sp-1": {"domain": "spotify", "name": "Spotify"},
                }

        class _M:
            config = _Config()

        assert list_yandex_music_instances(_M()) == [("ym-a", "Main"), ("ym-b", "ym-b")]

    def test_no_config(self) -> None:
        assert list_yandex_music_instances(object()) == []
