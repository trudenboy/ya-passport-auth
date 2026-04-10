"""Hypothesis fuzz tests for CSRF pattern safety.

Threat model T6 — ensures the regex set cannot be tricked into
catastrophic backtracking by long random input.
"""

from __future__ import annotations

import time

from hypothesis import given, settings
from hypothesis import strategies as st

from ya_passport_auth.constants import CSRF_PATTERNS


@settings(max_examples=500)
@given(st.text(min_size=0, max_size=10_000))
def test_csrf_patterns_terminate_quickly(html: str) -> None:
    """Every pattern must return within 50ms even on hostile input."""
    t0 = time.monotonic()
    for pattern in CSRF_PATTERNS:
        pattern.search(html)
    elapsed = time.monotonic() - t0
    assert elapsed < 0.05, f"CSRF regex took {elapsed:.3f}s on {len(html)}-char input"
