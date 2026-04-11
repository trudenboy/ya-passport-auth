"""Tests for the shared token-exchange helpers."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from types import SimpleNamespace
from unittest.mock import patch

import aiohttp
import pytest
from aioresponses import aioresponses
from yarl import URL

from ya_passport_auth.config import ClientConfig
from ya_passport_auth.constants import MUSIC_TOKEN_URL, PASSPORT_API_URL, PASSPORT_URL
from ya_passport_auth.credentials import SecretStr
from ya_passport_auth.exceptions import InvalidCredentialsError
from ya_passport_auth.flows._token_exchange import (
    exchange_cookies_for_x_token,
    exchange_x_token_for_music_token,
)
from ya_passport_auth.http import SafeHttpClient
from ya_passport_auth.rate_limit import AsyncMinDelayLimiter

_TOKEN_URL = f"{PASSPORT_API_URL}/1/bundle/oauth/token_by_sessionid"
_TEST_X_TOKEN = "test-xtoken-0123456789abcdef"
_TEST_MUSIC_TOKEN = "test-musictoken-fedcba9876543210"
_JSON_CT = {"Content-Type": "application/json"}


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


class TestExchangeCookiesForXToken:
    async def test_success(
        self,
        http: SafeHttpClient,
        session: aiohttp.ClientSession,
    ) -> None:
        session.cookie_jar.update_cookies(
            {"Session_id": "test-session-id", "sessionid2": "test-session-id2"},
            response_url=URL(PASSPORT_URL),
        )
        with aioresponses() as m:
            m.post(
                _TOKEN_URL,
                status=200,
                payload={"access_token": _TEST_X_TOKEN},
                headers=_JSON_CT,
            )
            token = await exchange_cookies_for_x_token(http, session)
        assert isinstance(token, SecretStr)
        assert token.get_secret() == _TEST_X_TOKEN

    async def test_no_cookies_raises(
        self,
        http: SafeHttpClient,
        session: aiohttp.ClientSession,
    ) -> None:
        with pytest.raises(InvalidCredentialsError, match="no Yandex session cookies"):
            await exchange_cookies_for_x_token(http, session)

    async def test_missing_access_token_raises(
        self,
        http: SafeHttpClient,
        session: aiohttp.ClientSession,
    ) -> None:
        session.cookie_jar.update_cookies(
            {"Session_id": "test-session-id"},
            response_url=URL(PASSPORT_URL),
        )
        with aioresponses() as m:
            m.post(
                _TOKEN_URL,
                status=200,
                payload={"error": "invalid_grant"},
                headers=_JSON_CT,
            )
            with pytest.raises(InvalidCredentialsError, match="x_token"):
                await exchange_cookies_for_x_token(http, session)

    async def test_cookie_crlf_stripped(
        self,
        http: SafeHttpClient,
        session: aiohttp.ClientSession,
    ) -> None:
        fake_morsel = SimpleNamespace(value="evil\r\nX-Injected: yes")
        fake_cookies = {"Session_id": fake_morsel}

        with (
            patch.object(
                session.cookie_jar,
                "filter_cookies",
                return_value=fake_cookies,
            ),
            aioresponses() as m,
        ):
            m.post(
                _TOKEN_URL,
                status=200,
                payload={"access_token": _TEST_X_TOKEN},
                headers=_JSON_CT,
            )
            await exchange_cookies_for_x_token(http, session)

            calls = m.requests[("POST", URL(_TOKEN_URL))]
            sent_headers = calls[0].kwargs["headers"]
            cookie_header = sent_headers["Ya-Client-Cookie"]

        assert "\r" not in cookie_header
        assert "\n" not in cookie_header
        assert "evilX-Injected: yes" in cookie_header


class TestExchangeXTokenForMusicToken:
    async def test_success(self, http: SafeHttpClient) -> None:
        with aioresponses() as m:
            m.post(
                MUSIC_TOKEN_URL,
                status=200,
                payload={"access_token": _TEST_MUSIC_TOKEN},
                headers=_JSON_CT,
            )
            token = await exchange_x_token_for_music_token(http, SecretStr(_TEST_X_TOKEN))
        assert isinstance(token, SecretStr)
        assert token.get_secret() == _TEST_MUSIC_TOKEN

    async def test_missing_access_token_raises(self, http: SafeHttpClient) -> None:
        with aioresponses() as m:
            m.post(
                MUSIC_TOKEN_URL,
                status=200,
                payload={"error": "invalid_grant"},
                headers=_JSON_CT,
            )
            with pytest.raises(InvalidCredentialsError, match="music token"):
                await exchange_x_token_for_music_token(http, SecretStr(_TEST_X_TOKEN))
