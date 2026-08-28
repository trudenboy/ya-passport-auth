"""Tests for the unified MA error mapping."""

from __future__ import annotations

import pytest
from music_assistant_models.errors import LoginFailed, ResourceTemporarilyUnavailable

from ya_passport_auth.exceptions import (
    DeviceCodeTimeoutError,
    InvalidCredentialsError,
    NetworkError,
    QRTimeoutError,
    RateLimitedError,
    YaPassportError,
)
from ya_passport_auth.ma.errors import raise_mapped


class TestRaiseMapped:
    @pytest.mark.parametrize("exc", [NetworkError("boom"), RateLimitedError("slow down")])
    def test_transient_maps_to_temporarily_unavailable(self, exc: YaPassportError) -> None:
        with pytest.raises(ResourceTemporarilyUnavailable) as excinfo:
            raise_mapped(exc, context="Music token refresh")
        assert type(exc).__name__ in str(excinfo.value)

    @pytest.mark.parametrize("exc", [QRTimeoutError("t"), DeviceCodeTimeoutError("t")])
    def test_timeout_maps_to_login_failed(self, exc: YaPassportError) -> None:
        with pytest.raises(LoginFailed, match="timed out"):
            raise_mapped(exc, context="Device authentication")

    def test_denied_maps_to_login_failed(self) -> None:
        with pytest.raises(LoginFailed, match="denied"):
            raise_mapped(InvalidCredentialsError("nope"), context="Device authentication")

    def test_generic_maps_to_login_failed(self) -> None:
        with pytest.raises(LoginFailed, match="YaPassportError"):
            raise_mapped(YaPassportError("misc"), context="QR authentication")

    def test_messages_never_carry_library_details(self) -> None:
        # Library exception strings may embed request bodies or token
        # fragments — only the class name may surface.
        secret = "OAuth super-secret-token-value"
        with pytest.raises(LoginFailed) as excinfo:
            raise_mapped(YaPassportError(secret), context="X")
        assert secret not in str(excinfo.value)
