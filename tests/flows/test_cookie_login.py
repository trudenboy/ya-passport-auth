"""Tests for ``exchange_cookie_string_for_x_token``.

This was previously ``CookieLoginFlow.login``; the class wrapped a
single method with no state, so it was merged into
:mod:`ya_passport_auth.flows._token_exchange` as a free function.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator

import aiohttp
import pytest
from aioresponses import aioresponses
from yarl import URL

from ya_passport_auth.config import ClientConfig
from ya_passport_auth.constants import PASSPORT_TOKEN_BY_SESSIONID_URL
from ya_passport_auth.credentials import SecretStr
from ya_passport_auth.exceptions import InvalidCredentialsError
from ya_passport_auth.flows._token_exchange import exchange_cookie_string_for_x_token
from ya_passport_auth.http import SafeHttpClient
from ya_passport_auth.rate_limit import AsyncMinDelayLimiter

_TOKEN_URL = PASSPORT_TOKEN_BY_SESSIONID_URL
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


class TestExchangeCookieStringForXToken:
    async def test_success(self, http: SafeHttpClient) -> None:
        with aioresponses() as m:
            m.post(
                _TOKEN_URL,
                status=200,
                payload={"access_token": _TEST_X_TOKEN},
                headers=_JSON_CT,
            )
            token = await exchange_cookie_string_for_x_token(
                http,
                "Session_id=abc; sessionid2=def",
            )
        assert isinstance(token, SecretStr)
        assert token.get_secret() == _TEST_X_TOKEN

    async def test_empty_cookies_raises(self, http: SafeHttpClient) -> None:
        with pytest.raises(InvalidCredentialsError, match="empty"):
            await exchange_cookie_string_for_x_token(http, "")

    async def test_whitespace_cookies_raises(self, http: SafeHttpClient) -> None:
        with pytest.raises(InvalidCredentialsError, match="empty"):
            await exchange_cookie_string_for_x_token(http, "   ")

    async def test_rejected_cookies(self, http: SafeHttpClient) -> None:
        with aioresponses() as m:
            m.post(
                _TOKEN_URL,
                status=200,
                payload={"error": "invalid_grant"},
                headers=_JSON_CT,
            )
            with pytest.raises(InvalidCredentialsError, match="invalid_grant"):
                await exchange_cookie_string_for_x_token(http, "Session_id=expired")

    async def test_surfaces_errors_array(self, http: SafeHttpClient) -> None:
        # token_by_sessionid signals failure via
        # {"status":"error", "errors":["sessionid.invalid"]} — the
        # marker must reach callers for diagnostics.
        with aioresponses() as m:
            m.post(
                _TOKEN_URL,
                status=200,
                payload={"status": "error", "errors": ["sessionid.invalid"]},
                headers=_JSON_CT,
            )
            with pytest.raises(InvalidCredentialsError, match=r"sessionid\.invalid"):
                await exchange_cookie_string_for_x_token(
                    http,
                    "Session_id=stale; sessionid2=stale",
                )

    async def test_sends_correct_headers(self, http: SafeHttpClient) -> None:
        cookies = "Session_id=abc; sessionid2=def"
        with aioresponses() as m:
            m.post(
                _TOKEN_URL,
                status=200,
                payload={"access_token": _TEST_X_TOKEN},
                headers=_JSON_CT,
            )
            await exchange_cookie_string_for_x_token(http, cookies)

            calls = m.requests[("POST", URL(_TOKEN_URL))]
            sent_headers = calls[0].kwargs["headers"]
            assert sent_headers["Ya-Client-Host"] == "passport.yandex.ru"
            assert sent_headers["Ya-Client-Cookie"] == cookies

    async def test_crlf_stripped(self, http: SafeHttpClient) -> None:
        """CR/LF in raw cookie string must be stripped to prevent header injection."""
        malicious = "Session_id=abc\r\nX-Injected: evil"
        with aioresponses() as m:
            m.post(
                _TOKEN_URL,
                status=200,
                payload={"access_token": _TEST_X_TOKEN},
                headers=_JSON_CT,
            )
            await exchange_cookie_string_for_x_token(http, malicious)

            calls = m.requests[("POST", URL(_TOKEN_URL))]
            sent_cookie = calls[0].kwargs["headers"]["Ya-Client-Cookie"]
            assert "\r" not in sent_cookie
            assert "\n" not in sent_cookie
            assert sent_cookie == "Session_id=abcX-Injected: evil"
