"""Logging utilities with mandatory token redaction.

The library never logs raw tokens. Every logger returned by
:func:`get_logger` has a :class:`RedactingFilter` attached that
rewrites the fully-rendered message in place before any handler runs,
protecting threat-model items T1 (token leak via logs) and T12 (log
injection via CRLF).

The filter's regex set is intentionally small and anchored — it does
not try to be clever about arbitrary secret shapes. Catching the two
patterns that actually appear in Yandex responses (``OAuth <token>``
headers and long hex runs) plus refusing CR/LF is enough.
"""

from __future__ import annotations

import logging
import re

__all__ = ["RedactingFilter", "get_logger"]

_REDACTED = "***"
_LOGGER_ROOT = "ya_passport_auth"

# ``OAuth <token>`` — the header shape returned by passport exchange
# endpoints. Match a long run of token-safe characters.
_OAUTH_RE = re.compile(r"OAuth\s+[A-Za-z0-9._\-]{8,}")

# Long runs of token-shaped characters (32+) — catches both hex tokens
# (x_token / music_token) and base64url-ish tokens without hitting short
# IDs, UIDs, or status codes. The character class matches the tokens
# Passport and Music actually emit; it is deliberately broader than
# strict hex so base64-padded values (``.``/``-``/``_``) are also
# redacted.
_LONG_TOKEN_RE = re.compile(r"\b[0-9a-zA-Z._\-]{32,}\b")

# CR/LF — collapsed to a visible marker so a single log entry cannot
# forge a second line (T12).
_CRLF_RE = re.compile(r"[\r\n]+")


def _scrub(text: str) -> str:
    text = _OAUTH_RE.sub(f"OAuth {_REDACTED}", text)
    text = _LONG_TOKEN_RE.sub(_REDACTED, text)
    return _CRLF_RE.sub(" | ", text)


class RedactingFilter(logging.Filter):
    """Scrub rendered log messages of token-like strings and CRLF.

    Applied to every logger returned by :func:`get_logger`.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Rewrite the record's message in place and always admit it."""
        # Render first so the filter sees the final message exactly as
        # handlers would have — including any ``%s`` substitutions.
        try:
            rendered = record.getMessage()
        except (TypeError, ValueError):
            rendered = str(record.msg)
        record.msg = _scrub(rendered)
        record.args = None
        return True


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced logger with :class:`RedactingFilter` attached.

    ``name`` is appended to the library root namespace — callers should
    pass a leaf name like ``"qr"`` or ``"http"``.
    """
    full_name = f"{_LOGGER_ROOT}.{name}" if name else _LOGGER_ROOT
    logger = logging.getLogger(full_name)
    # Attach the filter exactly once. Calling ``get_logger`` repeatedly
    # on the same name must be a no-op.
    if not any(isinstance(f, RedactingFilter) for f in logger.filters):
        logger.addFilter(RedactingFilter())
    return logger
