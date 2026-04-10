"""Tests for the QR login flow.

Covers CSRF extraction (4 pattern variants + missing), QR session
creation, QR status polling, x_token exchange, and music_token exchange.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import aiohttp
import pytest
from aioresponses import aioresponses
from yarl import URL

from ya_passport_auth.config import ClientConfig
from ya_passport_auth.constants import (
    MUSIC_TOKEN_URL,
    PASSPORT_API_URL,
    PASSPORT_URL,
)
from ya_passport_auth.credentials import SecretStr
from ya_passport_auth.exceptions import (
    AuthFailedError,
    CsrfExtractionError,
    InvalidCredentialsError,
)
from ya_passport_auth.flows.qr import QrLoginFlow, QrSession
from ya_passport_auth.http import SafeHttpClient
from ya_passport_auth.rate_limit import AsyncMinDelayLimiter

FIXTURES = Path(__file__).parent.parent / "fixtures"

_AM_URL = f"{PASSPORT_URL}/am?app_platform=android"
_SUBMIT_URL = f"{PASSPORT_URL}/registration-validations/auth/password/submit"
_STATUS_URL = f"{PASSPORT_URL}/auth/new/magic/status/"
_TOKEN_URL = f"{PASSPORT_API_URL}/1/bundle/oauth/token_by_sessionid"

_TEST_TRACK_ID = "test-track-id-0123456789"
_TEST_CSRF = "test-csrf-input-attr-01234567890"
_TEST_X_TOKEN = "test-xtoken-0123456789abcdef"
_TEST_MUSIC_TOKEN = "test-musictoken-fedcba9876543210"

_JSON_CT = {"Content-Type": "application/json"}
_HTML_CT = {"Content-Type": "text/html; charset=utf-8"}


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
def flow(http: SafeHttpClient, session: aiohttp.ClientSession) -> QrLoginFlow:
    return QrLoginFlow(http=http, session=session)


# ------------------------------------------------------------------ #
# CSRF extraction
# ------------------------------------------------------------------ #
class TestCsrfExtraction:
    @pytest.mark.parametrize(
        ("fixture_file", "expected_csrf"),
        [
            ("csrf_input_attr.html", "test-csrf-input-attr-01234567890"),
            ("csrf_js_single.html", "test-csrf-js-single-01234567890"),
            ("csrf_json_script.html", "test-csrf-json-script-01234567890"),
            ("csrf_window_global.html", "test-csrf-window-global-01234567890"),
        ],
    )
    async def test_csrf_patterns(
        self, flow: QrLoginFlow, fixture_file: str, expected_csrf: str
    ) -> None:
        html = (FIXTURES / fixture_file).read_text()
        with aioresponses() as m:
            m.get(_AM_URL, status=200, body=html, headers=_HTML_CT)
            m.post(
                _SUBMIT_URL,
                status=200,
                payload={
                    "status": "ok",
                    "track_id": _TEST_TRACK_ID,
                    "csrf_token": _TEST_CSRF,
                },
                headers=_JSON_CT,
            )
            qr = await flow.get_qr()

            # Verify the extracted CSRF was actually sent to the submit endpoint.
            calls = m.requests[("POST", URL(_SUBMIT_URL))]
            posted_csrf = calls[0].kwargs["data"]["csrf_token"]
            assert posted_csrf == expected_csrf
        assert qr.track_id == _TEST_TRACK_ID

    async def test_csrf_missing_raises(self, flow: QrLoginFlow) -> None:
        html = (FIXTURES / "csrf_missing.html").read_text()
        with aioresponses() as m:
            m.get(_AM_URL, status=200, body=html, headers=_HTML_CT)
            with pytest.raises(CsrfExtractionError):
                await flow.get_qr()


# ------------------------------------------------------------------ #
# QR session creation
# ------------------------------------------------------------------ #
class TestGetQr:
    async def test_returns_qr_session(self, flow: QrLoginFlow) -> None:
        html = (FIXTURES / "csrf_input_attr.html").read_text()
        with aioresponses() as m:
            m.get(_AM_URL, status=200, body=html, headers=_HTML_CT)
            m.post(
                _SUBMIT_URL,
                status=200,
                payload={
                    "status": "ok",
                    "track_id": _TEST_TRACK_ID,
                    "csrf_token": _TEST_CSRF,
                },
                headers=_JSON_CT,
            )
            qr = await flow.get_qr()

        assert isinstance(qr, QrSession)
        assert qr.track_id == _TEST_TRACK_ID
        assert qr.csrf_token == _TEST_CSRF
        assert "track_id=" in qr.qr_url

    async def test_submit_not_ok_raises(self, flow: QrLoginFlow) -> None:
        html = (FIXTURES / "csrf_input_attr.html").read_text()
        with aioresponses() as m:
            m.get(_AM_URL, status=200, body=html, headers=_HTML_CT)
            m.post(
                _SUBMIT_URL,
                status=200,
                payload={"status": "error", "errors": ["captcha"]},
                headers=_JSON_CT,
            )
            with pytest.raises(AuthFailedError):
                await flow.get_qr()

    async def test_missing_track_id_raises(self, flow: QrLoginFlow) -> None:
        html = (FIXTURES / "csrf_input_attr.html").read_text()
        with aioresponses() as m:
            m.get(_AM_URL, status=200, body=html, headers=_HTML_CT)
            m.post(
                _SUBMIT_URL,
                status=200,
                payload={"status": "ok"},
                headers=_JSON_CT,
            )
            with pytest.raises(AuthFailedError):
                await flow.get_qr()


# ------------------------------------------------------------------ #
# QR status check
# ------------------------------------------------------------------ #
class TestCheckStatus:
    async def test_pending(self, flow: QrLoginFlow) -> None:
        qr = QrSession(track_id=_TEST_TRACK_ID, csrf_token=_TEST_CSRF, qr_url="http://x")
        with aioresponses() as m:
            m.post(
                _STATUS_URL,
                status=200,
                payload={"status": "pending"},
                headers=_JSON_CT,
            )
            assert await flow.check_status(qr) is False

    async def test_ok(self, flow: QrLoginFlow) -> None:
        qr = QrSession(track_id=_TEST_TRACK_ID, csrf_token=_TEST_CSRF, qr_url="http://x")
        with aioresponses() as m:
            m.post(
                _STATUS_URL,
                status=200,
                payload={"status": "ok"},
                headers=_JSON_CT,
            )
            assert await flow.check_status(qr) is True


# ------------------------------------------------------------------ #
# x_token exchange
# ------------------------------------------------------------------ #
class TestGetXToken:
    async def test_success(
        self,
        flow: QrLoginFlow,
        session: aiohttp.ClientSession,
    ) -> None:
        # Simulate session cookies from a successful QR flow.
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
            token = await flow.get_x_token()
        assert isinstance(token, SecretStr)
        assert token.get_secret() == _TEST_X_TOKEN

    async def test_no_cookies_raises(self, flow: QrLoginFlow) -> None:
        with pytest.raises(InvalidCredentialsError):
            await flow.get_x_token()

    async def test_missing_access_token_raises(
        self,
        flow: QrLoginFlow,
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
            with pytest.raises(InvalidCredentialsError):
                await flow.get_x_token()

    async def test_cookie_crlf_stripped(
        self,
        flow: QrLoginFlow,
        session: aiohttp.ClientSession,
    ) -> None:
        """A cookie value containing CR/LF must never land verbatim in
        ``Ya-Client-Cookie`` — otherwise the header would be split and
        an attacker who controlled a cookie value could inject arbitrary
        additional headers (T12).

        We can't stuff a CRLF value into a real ``http.cookies.Morsel``
        on modern Python (3.13.13+ rejects control characters at
        ``Morsel.set`` time), so we use a duck-typed stand-in — the QR
        flow only reads ``.value`` off whatever the cookie jar yields.
        """
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
            await flow.get_x_token()

            calls = m.requests[("POST", URL(_TOKEN_URL))]
            assert len(calls) == 1
            sent_headers = calls[0].kwargs["headers"]
            cookie_header = sent_headers["Ya-Client-Cookie"]

        assert "\r" not in cookie_header
        assert "\n" not in cookie_header
        # The rest of the value must be preserved — only CR/LF is removed.
        assert "evilX-Injected: yes" in cookie_header


# ------------------------------------------------------------------ #
# Music token exchange
# ------------------------------------------------------------------ #
class TestGetMusicToken:
    async def test_success(self, flow: QrLoginFlow) -> None:
        with aioresponses() as m:
            m.post(
                MUSIC_TOKEN_URL,
                status=200,
                payload={"access_token": _TEST_MUSIC_TOKEN},
                headers=_JSON_CT,
            )
            token = await flow.get_music_token(SecretStr(_TEST_X_TOKEN))
        assert isinstance(token, SecretStr)
        assert token.get_secret() == _TEST_MUSIC_TOKEN

    async def test_missing_access_token_raises(self, flow: QrLoginFlow) -> None:
        with aioresponses() as m:
            m.post(
                MUSIC_TOKEN_URL,
                status=200,
                payload={"error": "invalid_grant"},
                headers=_JSON_CT,
            )
            with pytest.raises(InvalidCredentialsError):
                await flow.get_music_token(SecretStr(_TEST_X_TOKEN))
