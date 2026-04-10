"""Smoke test: the package is importable and exposes a version string."""

from __future__ import annotations

import ya_passport_auth


def test_version_importable() -> None:
    assert isinstance(ya_passport_auth.__version__, str)
    assert ya_passport_auth.__version__  # non-empty
