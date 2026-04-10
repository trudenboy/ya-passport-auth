"""Hypothesis fuzz tests for CSRF pattern safety.

Threat model T6 — ensures the regex set cannot be tricked into
catastrophic backtracking by long random input.
"""

from __future__ import annotations

from datetime import timedelta

from hypothesis import given, settings
from hypothesis import strategies as st

from ya_passport_auth.constants import CSRF_PATTERNS


@settings(max_examples=500, deadline=timedelta(milliseconds=200))
@given(st.text(min_size=0, max_size=10_000))
def test_csrf_patterns_terminate_quickly(html: str) -> None:
    """Every pattern must finish within the Hypothesis deadline on any input."""
    for pattern in CSRF_PATTERNS:
        pattern.search(html)
