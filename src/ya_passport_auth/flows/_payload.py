"""Shared payload-extraction helpers for flow modules.

Every flow that parses a JSON response from Yandex must pull
required fields out of a ``dict[str, object]`` while rejecting
missing/empty/wrong-type values with :class:`AuthFailedError`.
Centralizing these checks here keeps the per-flow modules focused on
their HTTP choreography rather than payload validation, and ensures
all flows surface payload problems with the same diagnostics.
"""

from __future__ import annotations

from ya_passport_auth.exceptions import AuthFailedError

__all__ = ["require_int", "require_str"]


def require_str(payload: dict[str, object], key: str, endpoint: str) -> str:
    """Pull *key* from *payload* and require a non-empty trimmed string.

    Returns the trimmed value so callers do not need to strip again.
    Raises :class:`AuthFailedError` (carrying *endpoint*) if the field
    is missing, not a string, or contains only whitespace.
    """
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise AuthFailedError(
            f"response missing {key!r}",
            endpoint=endpoint,
        )
    return value.strip()


def require_int(payload: dict[str, object], key: str, endpoint: str) -> int:
    """Pull *key* from *payload* and require it to be a true ``int``.

    Rejects ``bool`` explicitly because ``isinstance(True, int)`` is
    ``True`` in Python and OAuth fields like ``expires_in`` should not
    silently accept booleans.
    """
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise AuthFailedError(
            f"response missing or non-integer {key!r}",
            endpoint=endpoint,
        )
    return value
