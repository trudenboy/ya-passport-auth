"""Tests for Glagol device token fetcher."""

from __future__ import annotations

from collections.abc import AsyncGenerator

import aiohttp
import pytest
from aioresponses import aioresponses

from ya_passport_auth.config import ClientConfig
from ya_passport_auth.credentials import SecretStr
from ya_passport_auth.exceptions import InvalidCredentialsError
from ya_passport_auth.flows.glagol import GlagolDeviceTokenFetcher
from ya_passport_auth.http import SafeHttpClient
from ya_passport_auth.rate_limit import AsyncMinDelayLimiter

_GLAGOL_URL = "https://quasar.yandex.net/glagol/token?device_id=device-123&platform=yandexstation"
_JSON_CT = {"Content-Type": "application/json"}
_TEST_MUSIC_TOKEN = "test-music-token-abcdef"


@pytest.fixture
def config() -> ClientConfig:
    return ClientConfig(min_request_interval_seconds=0.001)


@pytest.fixture
async def session() -> AsyncGenerator[aiohttp.ClientSession, None]:
    async with aiohttp.ClientSession() as s:
        yield s


@pytest.fixture
def http(session: aiohttp.ClientSession, config: ClientConfig) -> SafeHttpClient:
    limiter = AsyncMinDelayLimiter(min_interval_seconds=0.001)
    return SafeHttpClient(session=session, config=config, limiter=limiter)


@pytest.fixture
def fetcher(http: SafeHttpClient) -> GlagolDeviceTokenFetcher:
    return GlagolDeviceTokenFetcher(http=http)


class TestGlagolDeviceToken:
    async def test_success(self, fetcher: GlagolDeviceTokenFetcher) -> None:
        with aioresponses() as m:
            m.get(
                _GLAGOL_URL,
                status=200,
                payload={"status": "ok", "token": "test-glagol-device-token"},
                headers=_JSON_CT,
            )
            token = await fetcher.fetch(
                music_token=SecretStr(_TEST_MUSIC_TOKEN),
                device_id="device-123",
                platform="yandexstation",
            )
        assert isinstance(token, SecretStr)
        assert token.get_secret() == "test-glagol-device-token"

    async def test_missing_token_raises(self, fetcher: GlagolDeviceTokenFetcher) -> None:
        with aioresponses() as m:
            m.get(
                _GLAGOL_URL,
                status=200,
                payload={"status": "error"},
                headers=_JSON_CT,
            )
            with pytest.raises(InvalidCredentialsError):
                await fetcher.fetch(
                    music_token=SecretStr(_TEST_MUSIC_TOKEN),
                    device_id="device-123",
                    platform="yandexstation",
                )

    async def test_error_body_raises(self, fetcher: GlagolDeviceTokenFetcher) -> None:
        with aioresponses() as m:
            m.get(
                _GLAGOL_URL,
                status=200,
                payload={"status": "error", "error": "unauthorized"},
                headers=_JSON_CT,
            )
            with pytest.raises(InvalidCredentialsError):
                await fetcher.fetch(
                    music_token=SecretStr(_TEST_MUSIC_TOKEN),
                    device_id="device-123",
                    platform="yandexstation",
                )
