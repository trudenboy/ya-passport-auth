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

    async def test_rotation_invokes_apply_credentials_hook(self, passport: _Passport) -> None:
        # The hook is what delivers the rotated triple to the provider's live
        # session — skipping it leaves the consumed refresh_token in memory.
        passport.music_error = LoginFailed("x expired")
        received: list[Credentials] = []

        async def apply_credentials(creds: Credentials) -> None:
            received.append(creds)

        store = _Store(x_token="test-x-0123456789", refresh_token="test-refresh-0123456789")
        hooks = CascadeHooks(apply_credentials=apply_credentials)
        assert await _cascade(store, hooks).initialize() is True
        assert received == [passport.rotated]

    async def test_rotation_finalization_failure_returns_false_but_keeps_rotated(
        self, passport: _Passport, caplog: pytest.LogCaptureFixture
    ) -> None:
        # post_refresh failing right after a successful rotation must not be
        # reported as silent success — but the persisted rotated credentials
        # stay (they are fresh), and the reason is logged.
        passport.music_error = LoginFailed("x expired")

        async def post_refresh() -> bool:
            # Succeed for the music-refresh step is impossible here (music
            # refresh raises), so this only runs on the rotation path.
            return False

        store = _Store(x_token="test-x-0123456789", refresh_token="test-refresh-0123456789")
        hooks = CascadeHooks(post_refresh=post_refresh)
        with caplog.at_level("WARNING"):
            assert await _cascade(store, hooks).initialize() is False
        assert ("x_token", "test-x-rotated-0123456789") in store.sets
        assert ("x_token", None) not in store.sets
        assert any("finalization" in r.message for r in caplog.records)

    async def test_post_refresh_exception_treated_as_failure(self, passport: _Passport) -> None:
        # A hook blowing up (MA API drift) must behave like post_refresh
        # returning False, not propagate raw out of initialize().
        async def post_refresh() -> bool:
            msg = "provider hook exploded"
            raise RuntimeError(msg)

        store = _Store(x_token="test-x-0123456789")
        hooks = CascadeHooks(post_refresh=post_refresh)
        assert await _cascade(store, hooks).initialize() is False


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

    async def test_transient_error_calls_on_failure_and_propagates(
        self, passport: _Passport
    ) -> None:
        # Same contract as initialize(): transient errors propagate (so the
        # caller keeps credentials) and on_failure cleanup still runs.
        passport.music_error = ResourceTemporarilyUnavailable("blip")
        cleaned: list[str] = []

        async def on_failure() -> None:
            cleaned.append("cleanup")

        store = _Store(**_FULL)
        hooks = CascadeHooks(on_failure=on_failure)
        with pytest.raises(ResourceTemporarilyUnavailable):
            await _cascade(store, hooks).silent_reauth()
        assert cleaned == ["cleanup"]
        assert ("x_token", None) not in store.sets

    async def test_unexpected_error_maps_to_transient(self, passport: _Passport) -> None:
        passport.music_error = OSError("socket")
        store = _Store(**_FULL)
        with pytest.raises(ResourceTemporarilyUnavailable):
            await _cascade(store).silent_reauth()
        assert ("x_token", None) not in store.sets

    async def test_gives_up_calls_on_failure(self, passport: _Passport) -> None:
        # No refresh_token → rotation impossible → the cascade gives up; the
        # on_failure hook (e.g. close provider HTTP session) must still run.
        passport.music_error = LoginFailed("x expired")
        cleaned: list[str] = []

        async def on_failure() -> None:
            cleaned.append("cleanup")

        store = _Store(x_token="test-x-0123456789", music_token="test-music-0123456789")
        hooks = CascadeHooks(on_failure=on_failure)
        assert await _cascade(store, hooks).silent_reauth() is False
        assert cleaned == ["cleanup"]

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
        # refresh_token is single-use — a 401 storm must trigger exactly ONE
        # rotation; later waiters must observe the rotated values instead of
        # re-rotating with the already-consumed refresh_token.
        stale_x = "test-x-0123456789"

        async def refresh_music_token(x_token: SecretStr) -> SecretStr:
            await asyncio.sleep(0)  # real awaits suspend — the lock must cover this
            passport.music_calls += 1
            if x_token.get_secret() == stale_x:
                raise LoginFailed("x expired")
            return SecretStr("test-music-fresh-0123456789")

        async def refresh_credentials(x_token: SecretStr, refresh_token: SecretStr) -> Credentials:
            await asyncio.sleep(0)
            passport.rotate_calls += 1
            return passport.rotated

        store = _Store(**_FULL)
        cascade = _cascade(store)
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(cascade_mod, "refresh_music_token", refresh_music_token)
            mp.setattr(cascade_mod, "refresh_credentials", refresh_credentials)
            results = await asyncio.gather(*(cascade.silent_reauth() for _ in range(3)))

        assert all(results)
        assert passport.rotate_calls == 1
        # Waiters 2 and 3 read the rotated x_token inside the lock and
        # refresh the music token without burning another rotation.
        assert passport.music_calls == 3
