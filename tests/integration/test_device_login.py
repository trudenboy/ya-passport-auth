"""Integration tests for OAuth Device Flow facade methods."""

from __future__ import annotations

import logging

import pytest
from aioresponses import aioresponses

from ya_passport_auth.client import PassportClient
from ya_passport_auth.config import ClientConfig
from ya_passport_auth.constants import DEVICE_CODE_URL, OAUTH_TOKEN_URL
from ya_passport_auth.credentials import Credentials, SecretStr
from ya_passport_auth.exceptions import (
    DeviceCodeTimeoutError,
    InvalidCredentialsError,
)
from ya_passport_auth.models import DeviceCodeSession

_PROXY = "https://mobileproxy.passport.yandex.net"
_SHORT_INFO = f"{_PROXY}/1/bundle/account/short_info/?avatar_size=islands-300"
_OAUTH = "https://oauth.mobile.yandex.net"
_JSON_CT = {"Content-Type": "application/json"}

_TEST_DEVICE_CODE = "test-device-code-facade-0123456789"
_TEST_USER_CODE = "facedode"
_TEST_VERIFICATION_URL = "https://ya.ru/device"
_TEST_ACCESS_TOKEN = "test-access-token-facade-0123456789"
_TEST_REFRESH_TOKEN = "test-refresh-token-facade-0123456789"
_TEST_NEW_ACCESS = "test-new-access-facade-0123456789"
_TEST_NEW_REFRESH = "test-new-refresh-facade-0123456789"
_TEST_MUSIC_TOKEN = "test-music-token-facade-abcdef0123"


def _fast_config() -> ClientConfig:
    return ClientConfig(min_request_interval_seconds=0.001)


def _mock_device_code_success(m: aioresponses, interval: int = 1, expires_in: int = 30) -> None:
    m.post(
        DEVICE_CODE_URL,
        status=200,
        payload={
            "device_code": _TEST_DEVICE_CODE,
            "user_code": _TEST_USER_CODE,
            "verification_url": _TEST_VERIFICATION_URL,
            "expires_in": expires_in,
            "interval": interval,
        },
        headers=_JSON_CT,
    )


def _mock_token_success(
    m: aioresponses,
    access: str = _TEST_ACCESS_TOKEN,
    refresh: str = _TEST_REFRESH_TOKEN,
) -> None:
    m.post(
        OAUTH_TOKEN_URL,
        status=200,
        payload={
            "access_token": access,
            "refresh_token": refresh,
            "expires_in": 31_536_000,
            "token_type": "bearer",
        },
        headers=_JSON_CT,
    )


def _mock_token_pending(m: aioresponses) -> None:
    m.post(
        OAUTH_TOKEN_URL,
        status=400,
        payload={"error": "authorization_pending"},
        headers=_JSON_CT,
    )


def _mock_token_slow_down(m: aioresponses) -> None:
    m.post(
        OAUTH_TOKEN_URL,
        status=400,
        payload={"error": "slow_down"},
        headers=_JSON_CT,
    )


def _mock_music_exchange(m: aioresponses) -> None:
    m.post(
        f"{_OAUTH}/1/token",
        status=200,
        payload={"access_token": _TEST_MUSIC_TOKEN},
        headers=_JSON_CT,
    )


def _mock_short_info(m: aioresponses, uid: int = 12345, login: str = "device.user") -> None:
    m.get(
        _SHORT_INFO,
        status=200,
        payload={"uid": uid, "display_login": login},
        headers=_JSON_CT,
    )


class TestLoginDeviceCode:
    async def test_sync_callback_end_to_end(self) -> None:
        captured: list[DeviceCodeSession] = []

        def on_code(session: DeviceCodeSession) -> None:
            captured.append(session)

        async with PassportClient.create(config=_fast_config()) as client:
            with aioresponses() as m:
                _mock_device_code_success(m, interval=1, expires_in=30)
                _mock_token_success(m)
                _mock_music_exchange(m)
                _mock_short_info(m, uid=777, login="alice")

                creds = await client.login_device_code(
                    on_code=on_code,
                    poll_interval=0.01,
                )

        assert isinstance(creds, Credentials)
        assert creds.x_token.get_secret() == _TEST_ACCESS_TOKEN
        assert creds.music_token is not None
        assert creds.music_token.get_secret() == _TEST_MUSIC_TOKEN
        assert creds.refresh_token is not None
        assert creds.refresh_token.get_secret() == _TEST_REFRESH_TOKEN
        assert creds.uid == 777
        assert creds.display_login == "alice"
        assert len(captured) == 1
        assert captured[0].user_code == _TEST_USER_CODE
        assert captured[0].verification_url == _TEST_VERIFICATION_URL

    async def test_async_callback(self) -> None:
        seen: list[str] = []

        async def on_code(session: DeviceCodeSession) -> None:
            seen.append(session.user_code)

        async with PassportClient.create(config=_fast_config()) as client:
            with aioresponses() as m:
                _mock_device_code_success(m)
                _mock_token_success(m)
                _mock_music_exchange(m)
                _mock_short_info(m)

                await client.login_device_code(on_code=on_code, poll_interval=0.01)

        assert seen == [_TEST_USER_CODE]


class TestPollDeviceUntilConfirmed:
    async def test_separated_usage(self) -> None:
        async with PassportClient.create(config=_fast_config()) as client:
            with aioresponses() as m:
                _mock_device_code_success(m)
                session = await client.start_device_login()
                _mock_token_success(m)
                _mock_music_exchange(m)
                _mock_short_info(m)
                creds = await client.poll_device_until_confirmed(session, poll_interval=0.01)

        assert creds.x_token.get_secret() == _TEST_ACCESS_TOKEN
        assert creds.refresh_token is not None

    async def test_pending_then_success(self) -> None:
        async with PassportClient.create(config=_fast_config()) as client:
            with aioresponses() as m:
                _mock_device_code_success(m)
                session = await client.start_device_login()
                _mock_token_pending(m)
                _mock_token_pending(m)
                _mock_token_success(m)
                _mock_music_exchange(m)
                _mock_short_info(m)
                creds = await client.poll_device_until_confirmed(session, poll_interval=0.001)

        assert creds.x_token.get_secret() == _TEST_ACCESS_TOKEN

    async def test_slow_down_does_not_abort(self, caplog: pytest.LogCaptureFixture) -> None:
        caplog.set_level(logging.WARNING, logger="ya_passport_auth")

        async with PassportClient.create(config=_fast_config()) as client:
            with aioresponses() as m:
                _mock_device_code_success(m)
                session = await client.start_device_login()
                _mock_token_slow_down(m)
                _mock_token_pending(m)
                _mock_token_success(m)
                _mock_music_exchange(m)
                _mock_short_info(m)
                creds = await client.poll_device_until_confirmed(session, poll_interval=0.001)

        assert creds.x_token.get_secret() == _TEST_ACCESS_TOKEN
        assert any("slow_down" in r.getMessage() for r in caplog.records), (
            "slow_down should be logged at WARNING level"
        )

    async def test_timeout(self) -> None:
        async with PassportClient.create(config=_fast_config()) as client:
            with aioresponses() as m:
                _mock_device_code_success(m)
                session = await client.start_device_login()
                for _ in range(20):
                    _mock_token_pending(m)
                with pytest.raises(DeviceCodeTimeoutError):
                    await client.poll_device_until_confirmed(
                        session,
                        poll_interval=0.001,
                        total_timeout=0.02,
                    )

    async def test_should_cancel(self) -> None:
        async with PassportClient.create(config=_fast_config()) as client:
            with aioresponses() as m:
                _mock_device_code_success(m)
                session = await client.start_device_login()
                _mock_token_pending(m)

                calls = {"count": 0}

                def should_cancel() -> bool:
                    calls["count"] += 1
                    return calls["count"] > 1  # cancel on the second iteration

                with pytest.raises(InvalidCredentialsError, match="cancelled"):
                    await client.poll_device_until_confirmed(
                        session,
                        poll_interval=0.001,
                        should_cancel=should_cancel,
                    )

    async def test_zero_interval_raises(self) -> None:
        session = DeviceCodeSession(
            device_code=SecretStr(_TEST_DEVICE_CODE),
            user_code=_TEST_USER_CODE,
            verification_url=_TEST_VERIFICATION_URL,
            expires_in=30,
            interval=5,
        )
        async with PassportClient.create(config=_fast_config()) as client:
            with pytest.raises(ValueError, match="poll_interval must be positive"):
                await client.poll_device_until_confirmed(session, poll_interval=0.0)

    async def test_zero_timeout_raises(self) -> None:
        session = DeviceCodeSession(
            device_code=SecretStr(_TEST_DEVICE_CODE),
            user_code=_TEST_USER_CODE,
            verification_url=_TEST_VERIFICATION_URL,
            expires_in=30,
            interval=5,
        )
        async with PassportClient.create(config=_fast_config()) as client:
            with pytest.raises(ValueError, match="total_timeout must be positive"):
                await client.poll_device_until_confirmed(session, total_timeout=0.0)


class TestRefreshCredentials:
    async def test_happy_path(self) -> None:
        creds = Credentials(
            x_token=SecretStr("old-x-token-0123456789abcdef"),
            music_token=SecretStr("old-music-token-0123456789abcdef"),
            refresh_token=SecretStr(_TEST_REFRESH_TOKEN),
        )
        async with PassportClient.create(config=_fast_config()) as client:
            with aioresponses() as m:
                _mock_token_success(m, access=_TEST_NEW_ACCESS, refresh=_TEST_NEW_REFRESH)
                _mock_music_exchange(m)
                _mock_short_info(m, uid=42, login="refreshed.user")
                new_creds = await client.refresh_credentials(creds)

        assert new_creds.x_token.get_secret() == _TEST_NEW_ACCESS
        assert new_creds.refresh_token is not None
        assert new_creds.refresh_token.get_secret() == _TEST_NEW_REFRESH
        assert new_creds.music_token is not None
        assert new_creds.music_token.get_secret() == _TEST_MUSIC_TOKEN
        assert new_creds.uid == 42
        assert new_creds.display_login == "refreshed.user"

    async def test_missing_refresh_token(self) -> None:
        creds = Credentials(
            x_token=SecretStr(_TEST_ACCESS_TOKEN),
            music_token=SecretStr(_TEST_MUSIC_TOKEN),
        )
        async with PassportClient.create(config=_fast_config()) as client:
            with pytest.raises(InvalidCredentialsError, match="no refresh_token"):
                await client.refresh_credentials(creds)

    async def test_invalid_grant(self) -> None:
        creds = Credentials(
            x_token=SecretStr(_TEST_ACCESS_TOKEN),
            music_token=SecretStr(_TEST_MUSIC_TOKEN),
            refresh_token=SecretStr(_TEST_REFRESH_TOKEN),
        )
        async with PassportClient.create(config=_fast_config()) as client:
            with aioresponses() as m:
                m.post(
                    OAUTH_TOKEN_URL,
                    status=400,
                    payload={"error": "invalid_grant"},
                    headers=_JSON_CT,
                )
                with pytest.raises(InvalidCredentialsError, match="rejected"):
                    await client.refresh_credentials(creds)


class TestAccountInfoFallback:
    async def test_missing_account_info_preserves_refresh_token(self) -> None:
        """When short_info fails, refresh_token must still be populated on Credentials."""
        async with PassportClient.create(config=_fast_config()) as client:
            with aioresponses() as m:
                _mock_device_code_success(m)
                session = await client.start_device_login()
                _mock_token_success(m)
                _mock_music_exchange(m)
                m.get(
                    _SHORT_INFO,
                    status=200,
                    payload={"status_code": 401},
                    headers=_JSON_CT,
                )
                creds = await client.poll_device_until_confirmed(session, poll_interval=0.01)

        assert creds.uid is None
        assert creds.display_login is None
        assert creds.refresh_token is not None
        assert creds.refresh_token.get_secret() == _TEST_REFRESH_TOKEN
