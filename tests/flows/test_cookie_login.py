"""Tests for the cookie login flow."""

from __future__ import annotations

from collections.abc import AsyncGenerator

import aiohttp
import pytest
from aioresponses import aioresponses
from yarl import URL

from ya_passport_auth.config import ClientConfig
from ya_passport_auth.constants import PASSPORT_API_URL
from ya_passport_auth.credentials import SecretStr
from ya_passport_auth.exceptions import InvalidCredentialsError
from ya_passport_auth.flows.cookie_login import CookieLoginFlow
from ya_passport_auth.http import SafeHttpClient
from ya_passport_auth.rate_limit import AsyncMinDelayLimiter

_TOKEN_URL = f"{PASSPORT_API_URL}/1/bundle/oauth/token_by_sessionid"
_TEST_X_TOKEN = "test-xtoken-cookies-0123456789"
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


@pytest.fixture
def flow(http: SafeHttpClient) -> CookieLoginFlow:
    return CookieLoginFlow(http=http)


class TestCookieLogin:
    async def test_login_success(self, flow: CookieLoginFlow) -> None:
        with aioresponses() as m:
            m.post(
                _TOKEN_URL,
                status=200,
                payload={"access_token": _TEST_X_TOKEN},
                headers=_JSON_CT,
            )
            token = await flow.login("Session_id=abc; sessionid2=def")
        assert isinstance(token, SecretStr)
        assert token.get_secret() == _TEST_X_TOKEN

    async def test_login_empty_cookies_raises(self, flow: CookieLoginFlow) -> None:
        with pytest.raises(InvalidCredentialsError, match="empty"):
            await flow.login("")

    async def test_login_whitespace_cookies_raises(self, flow: CookieLoginFlow) -> None:
        with pytest.raises(InvalidCredentialsError, match="empty"):
            await flow.login("   ")

    async def test_login_rejected_cookies(self, flow: CookieLoginFlow) -> None:
        with aioresponses() as m:
            m.post(
                _TOKEN_URL,
                status=200,
                payload={"error": "invalid_grant"},
                headers=_JSON_CT,
            )
            with pytest.raises(InvalidCredentialsError, match="x_token"):
                await flow.login("Session_id=expired")

    async def test_login_sends_correct_headers(self, flow: CookieLoginFlow) -> None:
        cookies = "Session_id=abc; sessionid2=def"
        with aioresponses() as m:
            m.post(
                _TOKEN_URL,
                status=200,
                payload={"access_token": _TEST_X_TOKEN},
                headers=_JSON_CT,
            )
            await flow.login(cookies)

            calls = m.requests[("POST", URL(_TOKEN_URL))]
            sent_headers = calls[0].kwargs["headers"]
            assert sent_headers["Ya-Client-Host"] == "passport.yandex.ru"
            assert sent_headers["Ya-Client-Cookie"] == cookies

    async def test_login_crlf_stripped(self, flow: CookieLoginFlow) -> None:
        """CR/LF in raw cookie string must be stripped to prevent header injection."""
        malicious = "Session_id=abc\r\nX-Injected: evil"
        with aioresponses() as m:
            m.post(
                _TOKEN_URL,
                status=200,
                payload={"access_token": _TEST_X_TOKEN},
                headers=_JSON_CT,
            )
            await flow.login(malicious)

            calls = m.requests[("POST", URL(_TOKEN_URL))]
            sent_cookie = calls[0].kwargs["headers"]["Ya-Client-Cookie"]
            assert "\r" not in sent_cookie
            assert "\n" not in sent_cookie
            assert sent_cookie == "Session_id=abcX-Injected: evil"
