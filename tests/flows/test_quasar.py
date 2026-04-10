"""Tests for Quasar CSRF fetcher."""

from __future__ import annotations

from collections.abc import AsyncGenerator

import aiohttp
import pytest
from aioresponses import aioresponses

from ya_passport_auth.config import ClientConfig
from ya_passport_auth.credentials import SecretStr
from ya_passport_auth.exceptions import CsrfExtractionError
from ya_passport_auth.flows.quasar import QuasarCsrfFetcher
from ya_passport_auth.http import SafeHttpClient
from ya_passport_auth.rate_limit import AsyncMinDelayLimiter

_QUASAR_URL = "https://iot.quasar.yandex.ru/m/v3/user/devices"
_JSON_CT = {"Content-Type": "application/json"}


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
def fetcher(http: SafeHttpClient) -> QuasarCsrfFetcher:
    return QuasarCsrfFetcher(http=http)


class TestQuasarCsrf:
    async def test_success(self, fetcher: QuasarCsrfFetcher) -> None:
        with aioresponses() as m:
            m.get(
                _QUASAR_URL,
                status=200,
                payload={"status": "ok", "request_id": "abc123"},
                headers={**_JSON_CT, "x-csrf-token": "test-csrf-quasar-token"},
            )
            token = await fetcher.fetch()
        assert isinstance(token, SecretStr)
        assert token.get_secret() == "test-csrf-quasar-token"

    async def test_missing_header_raises(self, fetcher: QuasarCsrfFetcher) -> None:
        with aioresponses() as m:
            m.get(
                _QUASAR_URL,
                status=200,
                payload={"status": "ok"},
                headers=_JSON_CT,
            )
            with pytest.raises(CsrfExtractionError):
                await fetcher.fetch()
