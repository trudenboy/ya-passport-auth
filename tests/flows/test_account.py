"""Tests for ``AccountInfoFetcher`` — short_info endpoint."""

from __future__ import annotations

from collections.abc import AsyncGenerator

import aiohttp
import pytest
from aioresponses import aioresponses

from ya_passport_auth.config import ClientConfig
from ya_passport_auth.credentials import SecretStr
from ya_passport_auth.exceptions import AuthFailedError, InvalidCredentialsError
from ya_passport_auth.flows.account import AccountInfoFetcher
from ya_passport_auth.http import SafeHttpClient
from ya_passport_auth.models import AccountInfo
from ya_passport_auth.rate_limit import AsyncMinDelayLimiter

_SHORT_INFO_URL = "https://mobileproxy.passport.yandex.net/1/bundle/account/short_info/"
_JSON_CT = {"Content-Type": "application/json"}
_TEST_X_TOKEN = "test-xtoken-abcdef0123456789"


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
def fetcher(http: SafeHttpClient) -> AccountInfoFetcher:
    return AccountInfoFetcher(http=http)


class TestAccountInfoSuccess:
    async def test_returns_account_info(self, fetcher: AccountInfoFetcher) -> None:
        with aioresponses() as m:
            m.get(
                _SHORT_INFO_URL,
                status=200,
                payload={
                    "uid": 123456,
                    "display_login": "test.user",
                    "display_name": "Test User",
                    "public_id": "abc123",
                },
                headers=_JSON_CT,
            )
            info = await fetcher.fetch(SecretStr(_TEST_X_TOKEN))

        assert isinstance(info, AccountInfo)
        assert info.uid == 123456
        assert info.display_login == "test.user"
        assert info.display_name == "Test User"

    async def test_optional_fields_default_none(self, fetcher: AccountInfoFetcher) -> None:
        with aioresponses() as m:
            m.get(
                _SHORT_INFO_URL,
                status=200,
                payload={"uid": 999},
                headers=_JSON_CT,
            )
            info = await fetcher.fetch(SecretStr(_TEST_X_TOKEN))

        assert info.uid == 999
        assert info.display_login is None
        assert info.display_name is None


class TestAccountInfoErrors:
    async def test_401_raises_invalid_credentials(self, fetcher: AccountInfoFetcher) -> None:
        with aioresponses() as m:
            m.get(
                _SHORT_INFO_URL,
                status=200,
                payload={"status_code": 401, "error": "unauthorized"},
                headers=_JSON_CT,
            )
            with pytest.raises(InvalidCredentialsError):
                await fetcher.fetch(SecretStr(_TEST_X_TOKEN))

    async def test_403_raises_invalid_credentials(self, fetcher: AccountInfoFetcher) -> None:
        with aioresponses() as m:
            m.get(
                _SHORT_INFO_URL,
                status=200,
                payload={"status_code": 403, "error": "forbidden"},
                headers=_JSON_CT,
            )
            with pytest.raises(InvalidCredentialsError):
                await fetcher.fetch(SecretStr(_TEST_X_TOKEN))

    async def test_missing_uid_raises(self, fetcher: AccountInfoFetcher) -> None:
        with aioresponses() as m:
            m.get(
                _SHORT_INFO_URL,
                status=200,
                payload={"display_login": "user"},
                headers=_JSON_CT,
            )
            with pytest.raises(AuthFailedError):
                await fetcher.fetch(SecretStr(_TEST_X_TOKEN))


class TestXTokenValidator:
    async def test_valid_token(self, fetcher: AccountInfoFetcher) -> None:
        with aioresponses() as m:
            m.get(
                _SHORT_INFO_URL,
                status=200,
                payload={"uid": 123},
                headers=_JSON_CT,
            )
            assert await fetcher.validate(SecretStr(_TEST_X_TOKEN)) is True

    async def test_invalid_token(self, fetcher: AccountInfoFetcher) -> None:
        with aioresponses() as m:
            m.get(
                _SHORT_INFO_URL,
                status=200,
                payload={"status_code": 401, "error": "unauthorized"},
                headers=_JSON_CT,
            )
            assert await fetcher.validate(SecretStr(_TEST_X_TOKEN)) is False
