"""Credential primitives: ``SecretStr``, ``Credentials``, ``MemoryCredentialStore``.

Only ``SecretStr`` is implemented in Task 5. ``Credentials`` and
``MemoryCredentialStore`` are added in Task 6.

Security properties enforced here:

* ``SecretStr`` redacts itself in ``repr``/``str``/``format`` so a token
  cannot leak into logs or traceback messages.
* ``SecretStr`` is not picklable — it raises ``TypeError`` from
  ``__reduce_ex__``. This prevents accidental serialization to Redis,
  multiprocessing queues, on-disk caches, etc.
* ``__slots__`` means instances carry no ``__dict__`` and cannot accept
  arbitrary attributes.
"""

from __future__ import annotations

from typing import NoReturn, SupportsIndex

__all__ = ["SecretStr"]

_REDACTED = "***"


class SecretStr:
    """Opaque wrapper around a sensitive string value.

    The wrapped value is only accessible via :meth:`get_secret`. Every
    other means of stringifying the object — ``repr``, ``str``, ``format``,
    f-strings — returns ``"***"``.

    Pickling raises ``TypeError`` to block accidental cross-process leaks.

    Equality is intentionally **only** defined between two ``SecretStr``
    instances; comparing to a plain ``str`` always returns ``False``. This
    protects against accidental leakage through equality probes.
    """

    __slots__ = ("_value",)

    _value: str

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError(f"SecretStr expects a str, got {type(value).__name__}")
        if not value:
            raise ValueError("SecretStr value must not be empty")
        object.__setattr__(self, "_value", value)

    # ------------------------------------------------------------------ #
    # Access
    # ------------------------------------------------------------------ #
    def get_secret(self) -> str:
        """Return the underlying plaintext value.

        Callers must take care not to log or serialize the returned value.
        """
        return self._value

    # ------------------------------------------------------------------ #
    # Redacted representations
    # ------------------------------------------------------------------ #
    def __repr__(self) -> str:
        return f"SecretStr('{_REDACTED}')"

    def __str__(self) -> str:
        return _REDACTED

    def __format__(self, format_spec: str) -> str:
        # Ignoring the format spec is deliberate: it guarantees that no
        # format-string trick can ever coax the plaintext out.
        del format_spec
        return _REDACTED

    # ------------------------------------------------------------------ #
    # Equality / hashing
    # ------------------------------------------------------------------ #
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, SecretStr):
            return NotImplemented
        return self._value == other._value

    def __hash__(self) -> int:
        return hash(("ya_passport_auth.SecretStr", self._value))

    # ------------------------------------------------------------------ #
    # Serialization guards (T2)
    # ------------------------------------------------------------------ #
    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        raise TypeError("SecretStr instances are not picklable")

    def __reduce__(self) -> NoReturn:
        raise TypeError("SecretStr instances are not picklable")

    # Explicit copy hook — deepcopy is allowed (in-process only).
    def __deepcopy__(self, memo: dict[int, object]) -> SecretStr:
        del memo
        return SecretStr(self._value)

    def __copy__(self) -> SecretStr:
        return SecretStr(self._value)
