"""Credential primitives: ``SecretStr``, ``Credentials``, ``MemoryCredentialStore``.

Security properties enforced here:

* ``SecretStr`` redacts itself in ``repr``/``str``/``format`` so a token
  cannot leak into logs or traceback messages.
* ``SecretStr`` is not picklable — it raises ``TypeError`` from
  ``__reduce_ex__``. This prevents accidental serialization to Redis,
  multiprocessing queues, on-disk caches, etc.
* ``__slots__`` means instances carry no ``__dict__`` and cannot accept
  arbitrary attributes.
* ``Credentials`` is a frozen, slotted dataclass. It holds ``SecretStr``
  instances so it also refuses to pickle and redacts tokens in ``repr``.
* ``MemoryCredentialStore`` is the only in-tree store. Persistence is
  delegated to the caller (e.g. Music Assistant's encrypted config).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import NoReturn, SupportsIndex

__all__ = ["Credentials", "MemoryCredentialStore", "SecretStr"]

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
            return False
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


@dataclass(frozen=True, slots=True, eq=True)
class Credentials:
    """Bundle of tokens and non-secret metadata for a Yandex account.

    ``x_token`` is the single source of truth — every other token in the
    mobile Passport graph can be re-derived from it. ``music_token`` is
    cached here so consumers that only need music API access do not have
    to round-trip through the exchange endpoint on every call.

    The ``repr`` intentionally surfaces ``uid`` and ``display_login``
    (useful in logs) but only ever shows ``"***"`` for tokens because
    the fields are ``SecretStr`` instances.
    """

    x_token: SecretStr
    music_token: SecretStr | None = None
    uid: int | None = None
    display_login: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.x_token, SecretStr):
            raise TypeError(
                f"Credentials.x_token must be a SecretStr, got {type(self.x_token).__name__}",
            )
        if self.music_token is not None and not isinstance(self.music_token, SecretStr):
            raise TypeError(
                f"Credentials.music_token must be a SecretStr or None, "
                f"got {type(self.music_token).__name__}",
            )


class MemoryCredentialStore:
    """In-process, async-safe credential store.

    Holds at most one :class:`Credentials` value. Intended as a default
    for callers that persist credentials themselves (for example, Music
    Assistant's encrypted provider config). The store owns no disk or
    network state, so ``close`` is unnecessary.
    """

    __slots__ = ("_creds", "_lock")

    _creds: Credentials | None
    _lock: asyncio.Lock

    def __init__(self) -> None:
        object.__setattr__(self, "_creds", None)
        object.__setattr__(self, "_lock", asyncio.Lock())

    async def load(self) -> Credentials | None:
        """Return the stored credentials, or ``None`` if empty."""
        async with self._lock:
            return self._creds

    async def save(self, credentials: Credentials) -> None:
        """Replace the stored credentials."""
        if not isinstance(credentials, Credentials):
            raise TypeError(
                f"MemoryCredentialStore.save expects Credentials, got {type(credentials).__name__}",
            )
        async with self._lock:
            object.__setattr__(self, "_creds", credentials)

    async def clear(self) -> None:
        """Forget any stored credentials."""
        async with self._lock:
            object.__setattr__(self, "_creds", None)

    def __repr__(self) -> str:
        state = "empty" if self._creds is None else "loaded"
        return f"MemoryCredentialStore(state={state!r})"
