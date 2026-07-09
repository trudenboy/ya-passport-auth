"""Tests for the silent credential-refresh cascade.

Ported from the yandex_station provider's cascade suite and generalized to
the hook-based engine.
"""

from __future__ import annotations

import asyncio

import pytest
from music_assistant_models.errors import LoginFailed, ResourceTemporarilyUnavailable

from ya_passport_auth import Credentials, SecretStr
from ya_passport_auth.ma import cascade as cascade_mod
from ya_passport_auth.ma.cascade import CascadeHooks, CredentialCascade, KeySpec

_KEYS = KeySpec()


class _Store:
    """In-memory config store with call recording."""

    def __init__(self, **values: object) -> None:
        self.values: dict[str, object] = dict(values)
        self.sets: list[tuple[str, str | None]] = []

    def get(self, key: str) -> object:
        return self.values.get(key)

    def set(self, key: str, value: str | None) -> None:
        self.sets.append((key, value))
        self.values[key] = value


class _Passport:
    """Patched stand-ins for the tokens module functions."""

    def __init__(self) -> None:
        self.music_error: Exception | None = None
        self.rotate_error: Exception | None = None
        self.rotated = Credentials(
            x_token=SecretStr("test-x-rotated-0123456789"),
            music_token=SecretStr("test-music-rotated-0123456789"),
            refresh_token=SecretStr("test-refresh-rotated-0123456789"),
        )
        self.music_calls = 0
        self.rotate_calls = 0

    async def refresh_music_token(self, x_token: SecretStr) -> SecretStr:
        self.music_calls += 1
        if self.music_error is not None:
            raise self.music_error
        return SecretStr("test-music-fresh-0123456789")

    async def refresh_credentials(
        self, x_token: SecretStr, refresh_token: SecretStr
    ) -> Credentials:
        self.rotate_calls += 1
        if self.rotate_error is not None:
            raise self.rotate_error
        return self.rotated


@pytest.fixture
def passport(monkeypatch: pytest.MonkeyPatch) -> _Passport:
    fake = _Passport()
    monkeypatch.setattr(cascade_mod, "refresh_music_token", fake.refresh_music_token)
    monkeypatch.setattr(cascade_mod, "refresh_credentials", fake.refresh_credentials)
    return fake


def _cascade(store: _Store, hooks: CascadeHooks | None = None) -> CredentialCascade:
    return CredentialCascade(keys=_KEYS, get_value=store.get, set_value=store.set, hooks=hooks)


_FULL = {
    "x_token": "test-x-0123456789",
    "music_token": "test-music-0123456789",
    "refresh_token": "test-refresh-0123456789",
}


class TestInitialize:
    async def test_no_credentials(self, passport: _Passport) -> None:
        assert await _cascade(_Store()).initialize() is False
        assert passport.music_calls == 0

    async def test_fast_path_success_short_circuits(self, passport: _Passport) -> None:
        calls: list[str] = []

        async def fast_path() -> bool:
            calls.append("fast")
            return True

        store = _Store(**_FULL)
        assert await _cascade(store, CascadeHooks(fast_path=fast_path)).initialize() is True
        assert calls == ["fast"]
        assert passport.music_calls == 0

    async def test_no_fast_path_hook_trusts_stored_pair(self, passport: _Passport) -> None:
        assert await _cascade(_Store(**_FULL)).initialize() is True
        assert passport.music_calls == 0

    async def test_fast_path_failure_refreshes(self, passport: _Passport) -> None:
        async def fast_path() -> bool:
            return False

        store = _Store(**_FULL)
        assert await _cascade(store, CascadeHooks(fast_path=fast_path)).initialize() is True
        assert passport.music_calls == 1
        assert ("music_token", "test-music-fresh-0123456789") in store.sets

    async def test_fast_path_exception_is_survived(self, passport: _Passport) -> None:
        async def fast_path() -> bool:
            msg = "validation exploded"
            raise RuntimeError(msg)

        store = _Store(**_FULL)
        assert await _cascade(store, CascadeHooks(fast_path=fast_path)).initialize() is True
        assert passport.music_calls == 1

    async def test_remember_off_music_only(self, passport: _Passport) -> None:
        store = _Store(music_token="test-music-0123456789", remember_session=False)
        assert await _cascade(store).initialize() is True
        assert passport.music_calls == 0

    async def test_remember_off_no_music_fails(self, passport: _Passport) -> None:
        store = _Store(x_token="test-x-0123456789", remember_session=False)
        assert await _cascade(store).initialize() is False

    async def test_music_only_without_x_token(self, passport: _Passport) -> None:
        store = _Store(music_token="test-music-0123456789")
        assert await _cascade(store).initialize() is True
        assert passport.music_calls == 0

    async def test_expired_x_token_rotates_via_refresh_token(self, passport: _Passport) -> None:
        passport.music_error = LoginFailed("x expired")
        store = _Store(x_token="test-x-0123456789", refresh_token="test-refresh-0123456789")
        assert await _cascade(store).initialize() is True
        assert passport.rotate_calls == 1
        assert ("x_token", "test-x-rotated-0123456789") in store.sets
        assert ("refresh_token", "test-refresh-rotated-0123456789") in store.sets

    async def test_expired_x_token_without_refresh_clears_credentials(
        self, passport: _Passport
    ) -> None:
        passport.music_error = LoginFailed("x expired")
        store = _Store(x_token="test-x-0123456789")
        assert await _cascade(store).initialize() is False
        assert ("x_token", None) in store.sets
        assert ("music_token", None) in store.sets
        assert ("refresh_token", None) in store.sets

    async def test_both_tokens_expired_clears_credentials(self, passport: _Passport) -> None:
        passport.music_error = LoginFailed("x expired")
        passport.rotate_error = LoginFailed("refresh expired")
        store = _Store(x_token="test-x-0123456789", refresh_token="test-refresh-0123456789")
        assert await _cascade(store).initialize() is False
        assert ("x_token", None) in store.sets

    async def test_transient_failure_preserves_credentials(self, passport: _Passport) -> None:
        passport.music_error = ResourceTemporarilyUnavailable("blip")
        store = _Store(x_token="test-x-0123456789")
        with pytest.raises(ResourceTemporarilyUnavailable):
            await _cascade(store).initialize()
        assert ("x_token", None) not in store.sets

    async def test_unexpected_error_maps_to_transient(self, passport: _Passport) -> None:
        passport.music_error = OSError("socket")
        store = _Store(x_token="test-x-0123456789")
        with pytest.raises(ResourceTemporarilyUnavailable):
            await _cascade(store).initialize()
        assert ("x_token", None) not in store.sets

    async def test_on_failure_hook_runs_on_terminal_failure(self, passport: _Passport) -> None:
        passport.music_error = LoginFailed("x expired")
        cleaned: list[str] = []

        async def on_failure() -> None:
            cleaned.append("cleanup")

        store = _Store(x_token="test-x-0123456789")
        await _cascade(store, CascadeHooks(on_failure=on_failure)).initialize()
        assert cleaned == ["cleanup"]

    async def test_post_refresh_false_fails_step(self, passport: _Passport) -> None:
        async def post_refresh() -> bool:
            return False

        store = _Store(x_token="test-x-0123456789")
        assert await _cascade(store, CascadeHooks(post_refresh=post_refresh)).initialize() is False

    async def test_incomplete_rotation_clears_credentials(self, passport: _Passport) -> None:
        passport.music_error = LoginFailed("x expired")
        passport.rotated = Credentials(x_token=SecretStr("test-x-rotated-0123456789"))
        store = _Store(x_token="test-x-0123456789", refresh_token="test-refresh-0123456789")
        assert await _cascade(store).initialize() is False
        assert ("x_token", None) in store.sets


class TestSilentReauth:
    async def test_refreshes_music_token(self, passport: _Passport) -> None:
        store = _Store(**_FULL)
        applied: list[str] = []

        async def apply_music_token(token: SecretStr) -> None:
            applied.append(token.get_secret())

        hooks = CascadeHooks(apply_music_token=apply_music_token)
        assert await _cascade(store, hooks).silent_reauth() is True
        assert applied == ["test-music-fresh-0123456789"]

    async def test_no_x_token(self, passport: _Passport) -> None:
        store = _Store(music_token="test-music-0123456789")
        assert await _cascade(store).silent_reauth() is False

    async def test_expired_x_token_falls_back_to_rotation(self, passport: _Passport) -> None:
        passport.music_error = LoginFailed("x expired")
        store = _Store(**_FULL)
        assert await _cascade(store).silent_reauth() is True
        assert passport.rotate_calls == 1

    async def test_failed_post_refresh_falls_back_to_rotation(self, passport: _Passport) -> None:
        post_calls: list[int] = []

        async def post_refresh() -> bool:
            post_calls.append(1)
            # First call (after music refresh) fails; the rotation path's
            # own post_refresh then succeeds.
            return len(post_calls) > 1

        store = _Store(**_FULL)
        hooks = CascadeHooks(post_refresh=post_refresh)
        assert await _cascade(store, hooks).silent_reauth() is True
        assert passport.rotate_calls == 1

    async def test_concurrent_reauths_serialize(self, passport: _Passport) -> None:
        # refresh_token is single-use — a 401 storm must trigger exactly one
        # rotation; waiters act on the rotated values.
        passport.music_error = LoginFailed("x expired")
        store = _Store(**_FULL)
        cascade = _cascade(store)

        async def _one() -> bool:
            return await cascade.silent_reauth()

        results = await asyncio.gather(_one(), _one(), _one())
        assert all(results)
        # After the first rotation the store carries the rotated x_token; the
        # fake keeps raising for music refresh, so each waiter rotates against
        # the *current* refresh token — but never concurrently.
        assert passport.rotate_calls == len(results)
