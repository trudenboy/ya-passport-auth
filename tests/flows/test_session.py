"""Tests for ``PassportSessionRefresher`` — cookie refresh via x_token."""

from __future__ import annotations

from collections.abc import AsyncGenerator

import aiohttp
import pytest
from aioresponses import aioresponses

from ya_passport_auth.config import ClientConfig
from ya_passport_auth.credentials import SecretStr
from ya_passport_auth.exceptions import InvalidCredentialsError
from ya_passport_auth.flows.session import PassportSessionRefresher
from ya_passport_auth.http import SafeHttpClient
from ya_passport_auth.rate_limit import AsyncMinDelayLimiter

_AUTH_URL = "https://mobileproxy.passport.yandex.net/1/bundle/auth/x_token/"
_SESSION_URL = "https://passport.yandex.ru/auth/session/"
_JSON_CT = {"Content-Type": "application/json"}
_HTML_CT = {"Content-Type": "text/html; charset=utf-8"}
_TEST_X_TOKEN = "test-xtoken-0123456789abcdef"


@pytest.fixture
def config() -> ClientConfig:
    return ClientConfig(min_request_interval_seconds=0.001)


@pytest.fixture
async def session() -> AsyncGenerator[aiohttp.ClientSession, None]:
    jar = aiohttp.CookieJar(unsafe=True)
    async with aiohttp.ClientSession(cookie_jar=jar) as s:
        yield s


@pytest.fixture
def http(session: aiohttp.ClientSession, config: ClientConfig) -> SafeHttpClient:
    limiter = AsyncMinDelayLimiter(min_interval_seconds=0.001)
    return SafeHttpClient(session=session, config=config, limiter=limiter)


@pytest.fixture
def refresher(http: SafeHttpClient) -> PassportSessionRefresher:
    return PassportSessionRefresher(http=http)


class TestRefreshCookies:
    async def test_success(self, refresher: PassportSessionRefresher) -> None:
        with aioresponses() as m:
            m.post(
                _AUTH_URL,
                status=200,
                payload={
                    "status": "ok",
                    "passport_host": "https://passport.yandex.ru",
                    "track_id": "test-track-id",
                },
                headers=_JSON_CT,
            )
            m.get(
                _SESSION_URL,
                status=200,
                body="<html>ok</html>",
                headers=_HTML_CT,
            )
            await refresher.refresh(SecretStr(_TEST_X_TOKEN))

    async def test_missing_track_id_raises(self, refresher: PassportSessionRefresher) -> None:
        with aioresponses() as m:
            m.post(
                _AUTH_URL,
                status=200,
                payload={"status": "ok", "passport_host": "https://passport.yandex.ru"},
                headers=_JSON_CT,
            )
            with pytest.raises(InvalidCredentialsError, match="missing track_id"):
                await refresher.refresh(SecretStr(_TEST_X_TOKEN))

    async def test_auth_failure_raises(self, refresher: PassportSessionRefresher) -> None:
        with aioresponses() as m:
            m.post(
                _AUTH_URL,
                status=200,
                payload={"status": "error", "errors": ["token.invalid"]},
                headers=_JSON_CT,
            )
            with pytest.raises(InvalidCredentialsError):
                await refresher.refresh(SecretStr(_TEST_X_TOKEN))
