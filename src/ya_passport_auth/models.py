"""Data models used across the library."""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["AccountInfo"]


@dataclass(frozen=True, slots=True)
class AccountInfo:
    """Non-secret account metadata from the ``short_info`` endpoint."""

    uid: int
    display_login: str | None = None
    display_name: str | None = None
    public_id: str | None = None
