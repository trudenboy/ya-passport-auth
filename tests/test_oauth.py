"""Tests for the public caller-owned OAuth Device Flow client."""

from __future__ import annotations

from collections.abc import AsyncGenerator

import aiohttp
import pytest
from aioresponses import aioresponses
from yarl import URL

from ya_passport_auth import DeviceCodeSession, OAuthDeviceClient
from ya_passport_auth.config import ClientConfig
from ya_passport_auth.constants import DEVICE_CODE_URL, OAUTH_TOKEN_URL

_JSON_CT = {"Content-Type": "application/json"}
_DEVICE_CODE = "provider-device-code-0123456789"
_ACCESS_TOKEN = "provider-access-token-0123456789"
_REFRESH_TOKEN = "provider-refresh-token-0123456789"


@pytest.fixture
async def session() -> AsyncGenerator[aiohttp.ClientSession, None]:
    async with aiohttp.ClientSession() as client_session:
        yield client_session


def _config() -> ClientConfig:
    return ClientConfig(min_request_interval_seconds=0.001)


def _device_payload() -> dict[str, object]:
    return {
        "device_code": _DEVICE_CODE,
        "user_code": "ABCD-1234",
        "verification_url": "https://ya.ru/device",
        "expires_in": 300,
        "interval": 1,
    }


def _token_payload() -> dict[str, object]:
    return {
        "access_token": _ACCESS_TOKEN,
        "refresh_token": _REFRESH_TOKEN,
        "expires_in": 31_536_000,
    }


def _form_field(kwargs: dict[str, object], field: str) -> str:
    data = kwargs["data"]
    assert isinstance(data, dict)
    value = data[field]
    assert isinstance(value, str)
    return value


class TestOAuthDeviceClient:
    async def test_login_returns_unmodified_tokens_and_calls_sync_callback(
        self, session: aiohttp.ClientSession
    ) -> None:
        seen: list[DeviceCodeSession] = []
        client = OAuthDeviceClient(
            client_id="disk-client",
            client_secret="disk-secret",
            scope="cloud_api:disk.read",
            session=session,
            config=_config(),
        )
        with aioresponses() as mocked:
            mocked.post(DEVICE_CODE_URL, payload=_device_payload(), headers=_JSON_CT)
            mocked.post(OAUTH_TOKEN_URL, payload=_token_payload(), headers=_JSON_CT)
            tokens = await client.login_device_code(
                on_code=seen.append,
                poll_interval=0.001,
                device_id="ma-disk",
                device_name="Music Assistant",
            )

        assert seen[0].user_code == "ABCD-1234"
        assert tokens.access_token.get_secret() == _ACCESS_TOKEN
        assert tokens.refresh_token.get_secret() == _REFRESH_TOKEN
        device_call = mocked.requests[("POST", URL(DEVICE_CODE_URL))][0]
        token_call = mocked.requests[("POST", URL(OAUTH_TOKEN_URL))][0]
        assert _form_field(device_call.kwargs, "client_id") == "disk-client"
        assert _form_field(device_call.kwargs, "scope") == "cloud_api:disk.read"
        assert _form_field(device_call.kwargs, "device_id") == "ma-disk"
        assert _form_field(token_call.kwargs, "client_secret") == "disk-secret"

    async def test_login_awaits_async_callback(self, session: aiohttp.ClientSession) -> None:
        called = False

        async def on_code(_code: DeviceCodeSession) -> None:
            nonlocal called
            called = True

        client = OAuthDeviceClient(
            client_id="client",
            client_secret="secret",
            session=session,
            config=_config(),
        )
        with aioresponses() as mocked:
            mocked.post(DEVICE_CODE_URL, payload=_device_payload(), headers=_JSON_CT)
            mocked.post(OAUTH_TOKEN_URL, payload=_token_payload(), headers=_JSON_CT)
            await client.login_device_code(on_code=on_code, poll_interval=0.001)

        assert called

    async def test_refresh_accepts_plain_string(self, session: aiohttp.ClientSession) -> None:
        client = OAuthDeviceClient(
            client_id="client",
            client_secret="secret",
            session=session,
            config=_config(),
        )
        with aioresponses() as mocked:
            mocked.post(OAUTH_TOKEN_URL, payload=_token_payload(), headers=_JSON_CT)
            tokens = await client.refresh("old-refresh-token")
            call = mocked.requests[("POST", URL(OAUTH_TOKEN_URL))][0]

        assert tokens.access_token.get_secret() == _ACCESS_TOKEN
        assert _form_field(call.kwargs, "grant_type") == "refresh_token"
        assert _form_field(call.kwargs, "refresh_token") == "old-refresh-token"

    async def test_borrowed_session_is_not_closed(self, session: aiohttp.ClientSession) -> None:
        async with OAuthDeviceClient(
            client_id="client",
            client_secret="secret",
            session=session,
        ) as entered:
            assert isinstance(entered, OAuthDeviceClient)
        assert not session.closed

    async def test_create_closes_owned_session(self) -> None:
        owned_session: aiohttp.ClientSession | None = None
        async with OAuthDeviceClient.create(
            client_id="client",
            client_secret="secret",
            config=_config(),
        ) as client:
            owned_session = client._session
            assert not owned_session.closed

        assert owned_session.closed
