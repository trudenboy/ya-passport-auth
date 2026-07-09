"""Tests for the borrowed-credentials source (shared Yandex account)."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest
from music_assistant_models.enums import ProviderType
from music_assistant_models.errors import LoginFailed

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


class TestReadTokens:
    def test_reads_owner_tokens(self, clock: _Clock) -> None:
        mass = _Mass({"ym-1": _Owner({"token": "test-music-1", "x_token": "test-x-1"})})
        assert _source(mass, clock).read_tokens() == ("test-music-1", "test-x-1")

    def test_owner_not_loaded(self, clock: _Clock) -> None:
        with pytest.raises(LoginFailed, match="is not loaded"):
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
        assert source.read_tokens() == ("test-music-1", "test-x-1")


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
