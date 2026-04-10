"""Tests for ``Credentials`` and ``MemoryCredentialStore``.

Threat model mapping:
- T1 (token leak via logs/tracebacks): ``repr`` must not contain any token substring.
- T2 (token leak via pickling): ``Credentials`` must be unpickleable because it
  transitively contains ``SecretStr`` instances.
- T13 (credential exposure via ``vars()``/``__dict__``): frozen + slotted.
"""

from __future__ import annotations

import copy
import pickle
from dataclasses import FrozenInstanceError

import pytest

from ya_passport_auth.credentials import (
    Credentials,
    MemoryCredentialStore,
    SecretStr,
)

_X_TOKEN = "x-token-abcdef0123456789"
_MUSIC_TOKEN = "music-token-zyxwv9876543210"


def _creds(**overrides: object) -> Credentials:
    base: dict[str, object] = {
        "x_token": SecretStr(_X_TOKEN),
        "music_token": SecretStr(_MUSIC_TOKEN),
        "uid": 1234567890,
        "display_login": "test.user",
    }
    base.update(overrides)
    return Credentials(**base)  # type: ignore[arg-type]


class TestCredentialsConstruction:
    def test_all_fields(self) -> None:
        c = _creds()
        assert c.x_token.get_secret() == _X_TOKEN
        assert c.music_token is not None
        assert c.music_token.get_secret() == _MUSIC_TOKEN
        assert c.uid == 1234567890
        assert c.display_login == "test.user"

    def test_optional_fields_default_none(self) -> None:
        c = Credentials(x_token=SecretStr(_X_TOKEN))
        assert c.music_token is None
        assert c.uid is None
        assert c.display_login is None

    def test_x_token_required(self) -> None:
        with pytest.raises(TypeError):
            Credentials()  # type: ignore[call-arg]

    def test_x_token_must_be_secretstr(self) -> None:
        with pytest.raises(TypeError, match="SecretStr"):
            Credentials(x_token=_X_TOKEN)  # type: ignore[arg-type]

    def test_music_token_must_be_secretstr_if_provided(self) -> None:
        with pytest.raises(TypeError, match="SecretStr"):
            Credentials(
                x_token=SecretStr(_X_TOKEN),
                music_token=_MUSIC_TOKEN,  # type: ignore[arg-type]
            )


class TestCredentialsRedaction:
    def test_repr_hides_all_tokens(self) -> None:
        c = _creds()
        rendered = repr(c)
        assert _X_TOKEN not in rendered
        assert _MUSIC_TOKEN not in rendered
        assert "***" in rendered

    def test_repr_contains_safe_metadata(self) -> None:
        """Non-secret fields like ``uid``/``display_login`` are fine in repr."""
        c = _creds()
        rendered = repr(c)
        assert "1234567890" in rendered
        assert "test.user" in rendered

    def test_repr_with_missing_optional_tokens(self) -> None:
        c = Credentials(x_token=SecretStr(_X_TOKEN))
        rendered = repr(c)
        assert _X_TOKEN not in rendered
        assert "None" in rendered


class TestCredentialsImmutability:
    def test_frozen(self) -> None:
        c = _creds()
        with pytest.raises(FrozenInstanceError):
            c.uid = 42  # type: ignore[misc]

    def test_slotted_no_dict(self) -> None:
        c = _creds()
        with pytest.raises(AttributeError):
            getattr(c, "__dict__")  # noqa: B009

    def test_cannot_add_new_attribute(self) -> None:
        c = _creds()
        # frozen+slots dataclasses raise one of several errors depending on
        # the interpreter version — we only care that the write is rejected.
        with pytest.raises((FrozenInstanceError, AttributeError, TypeError)):
            setattr(c, "extra", "nope")  # noqa: B010


class TestCredentialsNotPickleable:
    def test_pickle_raises(self) -> None:
        c = _creds()
        with pytest.raises(TypeError):
            pickle.dumps(c)

    def test_deepcopy_allowed(self) -> None:
        c = _creds()
        other = copy.deepcopy(c)
        assert other == c
        assert other.x_token.get_secret() == _X_TOKEN


class TestCredentialsEquality:
    def test_equal_when_all_fields_match(self) -> None:
        assert _creds() == _creds()

    def test_not_equal_when_token_differs(self) -> None:
        other = Credentials(
            x_token=SecretStr("different-x"),
            music_token=SecretStr(_MUSIC_TOKEN),
            uid=1234567890,
            display_login="test.user",
        )
        assert _creds() != other

    def test_not_equal_to_unrelated_type(self) -> None:
        other: object = "credentials"
        assert _creds() != other


class TestMemoryCredentialStore:
    async def test_load_returns_none_when_empty(self) -> None:
        store = MemoryCredentialStore()
        assert await store.load() is None

    async def test_save_then_load(self) -> None:
        store = MemoryCredentialStore()
        c = _creds()
        await store.save(c)
        loaded = await store.load()
        assert loaded == c

    async def test_save_overwrites(self) -> None:
        store = MemoryCredentialStore()
        await store.save(_creds())
        new = Credentials(x_token=SecretStr("x-token-new-value"))
        await store.save(new)
        assert await store.load() == new

    async def test_clear_removes_credentials(self) -> None:
        store = MemoryCredentialStore()
        await store.save(_creds())
        await store.clear()
        assert await store.load() is None

    async def test_clear_when_empty_is_noop(self) -> None:
        store = MemoryCredentialStore()
        await store.clear()  # must not raise
        assert await store.load() is None

    async def test_store_repr_does_not_leak_tokens(self) -> None:
        store = MemoryCredentialStore()
        await store.save(_creds())
        rendered = repr(store)
        assert _X_TOKEN not in rendered
        assert _MUSIC_TOKEN not in rendered

    async def test_store_rejects_non_credentials(self) -> None:
        store = MemoryCredentialStore()
        with pytest.raises(TypeError):
            await store.save("not-a-credentials-object")  # type: ignore[arg-type]
