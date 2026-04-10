"""Tests for ``SecretStr`` — token wrapper that prevents accidental exposure.

Threat model mapping:
- T1 (token leak via logs/tracebacks): repr/str must redact.
- T2 (token leak via pickling): ``__reduce__`` must raise ``TypeError``.
- T13 (credential exposure via vars/__dict__): no accessible attributes.
"""

from __future__ import annotations

import copy
import pickle

import pytest

from ya_passport_auth.credentials import SecretStr

_KNOWN_SECRET = "super-secret-xyz-123"


class TestSecretStrRedaction:
    def test_repr_is_redacted(self) -> None:
        s = SecretStr(_KNOWN_SECRET)
        assert _KNOWN_SECRET not in repr(s)
        assert "***" in repr(s)

    def test_str_is_redacted(self) -> None:
        s = SecretStr(_KNOWN_SECRET)
        assert _KNOWN_SECRET not in str(s)
        assert str(s) == "***"

    def test_format_is_redacted(self) -> None:
        s = SecretStr(_KNOWN_SECRET)
        assert _KNOWN_SECRET not in f"{s}"
        assert _KNOWN_SECRET not in f"{s!r}"
        assert _KNOWN_SECRET not in format(s, "")

    def test_traceback_does_not_expose_secret(self) -> None:
        """Wrapping a SecretStr in an exception message must not leak it."""
        s = SecretStr(_KNOWN_SECRET)
        try:
            raise ValueError(f"bad value: {s}")
        except ValueError as exc:
            assert _KNOWN_SECRET not in str(exc)


class TestSecretStrAccess:
    def test_get_secret_returns_plain_value(self) -> None:
        s = SecretStr(_KNOWN_SECRET)
        assert s.get_secret() == _KNOWN_SECRET

    def test_empty_string_rejected(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            SecretStr("")

    def test_non_string_rejected(self) -> None:
        with pytest.raises(TypeError):
            SecretStr(123)  # type: ignore[arg-type]


class TestSecretStrEquality:
    def test_equal_instances(self) -> None:
        assert SecretStr(_KNOWN_SECRET) == SecretStr(_KNOWN_SECRET)

    def test_inequal_instances(self) -> None:
        assert SecretStr(_KNOWN_SECRET) != SecretStr("other")

    def test_not_equal_to_plain_string(self) -> None:
        # Intentional: prevents accidental equality with attacker-controlled
        # input or raw strings that could signal "we hold a token like X".
        assert SecretStr(_KNOWN_SECRET) != _KNOWN_SECRET

    def test_hashable_and_stable(self) -> None:
        a = SecretStr(_KNOWN_SECRET)
        b = SecretStr(_KNOWN_SECRET)
        assert hash(a) == hash(b)
        # Usable as dict key / set member
        assert {a: 1}[b] == 1


class TestSecretStrImmutability:
    def test_has_slots(self) -> None:
        s = SecretStr(_KNOWN_SECRET)
        # __slots__ means no __dict__ — getattr defers the check to runtime
        # so mypy does not statically short-circuit the assertion.
        with pytest.raises(AttributeError):
            getattr(s, "__dict__")  # noqa: B009

    def test_cannot_set_new_attrs(self) -> None:
        s = SecretStr(_KNOWN_SECRET)
        with pytest.raises(AttributeError):
            # Dynamic attribute set must fail because SecretStr uses __slots__.
            # Using setattr to avoid a compile-time mypy check — we want the
            # runtime guarantee to be exercised directly.
            setattr(s, "other", "x")  # noqa: B010


class TestSecretStrNotSerializable:
    def test_pickle_raises(self) -> None:
        s = SecretStr(_KNOWN_SECRET)
        with pytest.raises(TypeError, match="SecretStr"):
            pickle.dumps(s)

    def test_deepcopy_allowed(self) -> None:
        # Deep-copying a SecretStr is a legitimate in-process operation and
        # should work; only cross-process serialization is blocked.
        s = SecretStr(_KNOWN_SECRET)
        c = copy.deepcopy(s)
        assert c == s
        assert c.get_secret() == _KNOWN_SECRET

    def test_shallow_copy_allowed(self) -> None:
        s = SecretStr(_KNOWN_SECRET)
        c = copy.copy(s)
        assert c == s
        assert c.get_secret() == _KNOWN_SECRET

    def test_direct_reduce_call_raises(self) -> None:
        # Guard for any exotic code path that calls __reduce__ directly
        # (e.g. some custom serializers).
        s = SecretStr(_KNOWN_SECRET)
        with pytest.raises(TypeError):
            s.__reduce__()

    def test_equality_with_unrelated_type_returns_false(self) -> None:
        s = SecretStr(_KNOWN_SECRET)
        assert (s == 42) is False
        assert (s == object()) is False
