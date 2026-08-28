"""Tests for the Music Assistant credential helpers."""

from __future__ import annotations

from typing import Self

import pytest
from music_assistant_models.errors import (
    InvalidDataError,
    LoginFailed,
    ResourceTemporarilyUnavailable,
)

from ya_passport_auth import Credentials, PassportClient, SecretStr
from ya_passport_auth.exceptions import InvalidCredentialsError, NetworkError, YaPassportError
from ya_passport_auth.ma.flow import login_with_cookies, require_music_token


def _creds(*, music: bool = True) -> Credentials:
    return Credentials(
        x_token=SecretStr("test-x-token-0123456789"),
        music_token=SecretStr("test-music-token-0123456789") if music else None,
        refresh_token=SecretStr("test-refresh-token-0123456789"),
        display_login="renso",
    )


class _FakeClient:
    def __init__(self) -> None:
        self.error: YaPassportError | None = None
        self.seen_cookies: str | None = None

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None

    async def login_cookies(self, cookies: str) -> Credentials:
        self.seen_cookies = cookies
        if self.error is not None:
            raise self.error
        return _creds()


@pytest.fixture
def fake_client(monkeypatch: pytest.MonkeyPatch) -> _FakeClient:
    client = _FakeClient()

    def create(**_kwargs: object) -> _FakeClient:
        return client

    monkeypatch.setattr(PassportClient, "create", create)
    return client


class TestRequireMusicToken:
    def test_returns_secret(self) -> None:
        assert require_music_token(_creds(), flow="Device") == "test-music-token-0123456789"

    def test_raises_when_missing(self) -> None:
        with pytest.raises(LoginFailed, match="Device auth succeeded but no music token"):
            require_music_token(_creds(music=False), flow="Device")


class TestLoginWithCookies:
    async def test_raw_cookie_string(self, fake_client: _FakeClient) -> None:
        creds = await login_with_cookies("Session_id=abc; yandexuid=42")
        assert creds.music_token is not None
        assert fake_client.seen_cookies == "Session_id=abc; yandexuid=42"

    async def test_json_cookie_array(self, fake_client: _FakeClient) -> None:
        await login_with_cookies('[{"name": "Session_id", "value": "abc"}]')
        assert fake_client.seen_cookies == "Session_id=abc"

    async def test_empty_input(self) -> None:
        with pytest.raises(InvalidDataError, match="Empty"):
            await login_with_cookies("   ")

    @pytest.mark.parametrize(
        "bad",
        [
            "{}",
            '[{"name": "x"}]',
            '["not-an-object"]',
            "[broken json",
            '[{"value": "v"}]',
        ],
    )
    async def test_malformed_json(self, bad: str) -> None:
        with pytest.raises(InvalidDataError):
            await login_with_cookies(bad)

    async def test_no_kv_pairs(self) -> None:
        with pytest.raises(InvalidDataError, match="Invalid cookie format"):
            await login_with_cookies("just-some-garbage")

    @pytest.mark.parametrize(
        ("error", "expected"),
        [
            (NetworkError("net down"), ResourceTemporarilyUnavailable),
            (InvalidCredentialsError("no"), LoginFailed),
        ],
    )
    async def test_errors_are_mapped(
        self,
        fake_client: _FakeClient,
        error: YaPassportError,
        expected: type[Exception],
    ) -> None:
        fake_client.error = error
        with pytest.raises(expected):
            await login_with_cookies("Session_id=abc")
