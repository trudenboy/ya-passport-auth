"""Tests for token-maintenance wrappers with MA error mapping."""

from __future__ import annotations

from typing import Self

import pytest
from music_assistant_models.errors import LoginFailed, ResourceTemporarilyUnavailable

from ya_passport_auth import Credentials, PassportClient, SecretStr
from ya_passport_auth.exceptions import (
    AuthFailedError,
    InvalidCredentialsError,
    NetworkError,
    RateLimitedError,
    YaPassportError,
)
from ya_passport_auth.ma.tokens import refresh_credentials, refresh_music_token, validate_x_token

_X = SecretStr("test-x-token-0123456789")
_REFRESH = SecretStr("test-refresh-token-0123456789")


class _FakeClient:
    def __init__(self, *, error: Exception | None = None, valid: bool = True) -> None:
        self.error = error
        self.valid = valid

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None

    async def refresh_music_token(self, x_token: SecretStr) -> SecretStr:
        if self.error is not None:
            raise self.error
        return SecretStr("test-music-token-0123456789")

    async def refresh_credentials(self, creds: Credentials) -> Credentials:
        if self.error is not None:
            raise self.error
        return Credentials(
            x_token=SecretStr("test-x-token-rotated-0123"),
            music_token=SecretStr("test-music-token-rotated"),
            refresh_token=SecretStr("test-refresh-token-rotated"),
        )

    async def validate_x_token(self, x_token: SecretStr) -> bool:
        if self.error is not None:
            raise self.error
        return self.valid


@pytest.fixture
def fake_client(monkeypatch: pytest.MonkeyPatch) -> _FakeClient:
    client = _FakeClient()
    monkeypatch.setattr(PassportClient, "create", lambda config=None: client)
    return client


class TestRefreshMusicToken:
    async def test_success(self, fake_client: _FakeClient) -> None:
        token = await refresh_music_token(_X)
        assert token.get_secret() == "test-music-token-0123456789"

    async def test_transient(self, fake_client: _FakeClient) -> None:
        fake_client.error = RateLimitedError("429")
        with pytest.raises(ResourceTemporarilyUnavailable):
            await refresh_music_token(_X)

    async def test_terminal(self, fake_client: _FakeClient) -> None:
        fake_client.error = InvalidCredentialsError("expired")
        with pytest.raises(LoginFailed):
            await refresh_music_token(_X)

    async def test_unknown_server_error_is_transient(self, fake_client: _FakeClient) -> None:
        # Only an explicit rejection is terminal — a novel/unknown server
        # error must not cascade into clearing stored credentials.
        fake_client.error = AuthFailedError("unexpected token response")
        with pytest.raises(ResourceTemporarilyUnavailable):
            await refresh_music_token(_X)


class TestRefreshCredentials:
    async def test_success(self, fake_client: _FakeClient) -> None:
        creds = await refresh_credentials(_X, _REFRESH)
        assert creds.refresh_token is not None

    async def test_transient(self, fake_client: _FakeClient) -> None:
        fake_client.error = NetworkError("down")
        with pytest.raises(ResourceTemporarilyUnavailable):
            await refresh_credentials(_X, _REFRESH)

    async def test_terminal(self, fake_client: _FakeClient) -> None:
        fake_client.error = InvalidCredentialsError("refresh_token rejected")
        with pytest.raises(LoginFailed):
            await refresh_credentials(_X, _REFRESH)

    @pytest.mark.parametrize(
        "exc",
        [AuthFailedError("refresh_token error: internal_error"), YaPassportError("odd")],
    )
    async def test_unknown_oauth_error_is_transient(
        self, fake_client: _FakeClient, exc: Exception
    ) -> None:
        # A Yandex-side incident (200 + {"error": "internal_error"}) must not
        # be mistaken for a consumed refresh token — that would wipe the
        # stored credential triple while the token is still valid.
        fake_client.error = exc
        with pytest.raises(ResourceTemporarilyUnavailable):
            await refresh_credentials(_X, _REFRESH)


class TestValidateXToken:
    async def test_valid(self, fake_client: _FakeClient) -> None:
        assert await validate_x_token(_X) is True

    async def test_rejected(self, fake_client: _FakeClient) -> None:
        fake_client.error = YaPassportError("bad token")
        assert await validate_x_token(_X) is False

    @pytest.mark.parametrize("exc", [NetworkError("down"), RateLimitedError("429")])
    async def test_transient_reraised(self, fake_client: _FakeClient, exc: Exception) -> None:
        # Callers must be able to tell "Passport blip" from "token invalid".
        fake_client.error = exc
        with pytest.raises(type(exc)):
            await validate_x_token(_X)
