"""Tests for the QR login flow.

Covers CSRF extraction (4 pattern variants + missing), QR session
creation, and QR status polling. Token exchange tests live in
``test_token_exchange.py``.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from pathlib import Path

import aiohttp
import pytest
from aioresponses import aioresponses
from yarl import URL

from ya_passport_auth.config import ClientConfig
from ya_passport_auth.constants import (
    PASSPORT_BFF_URL,
    PASSPORT_URL,
)
from ya_passport_auth.exceptions import (
    AuthFailedError,
    CsrfExtractionError,
)
from ya_passport_auth.flows.qr import QrLoginFlow, QrSession
from ya_passport_auth.http import SafeHttpClient
from ya_passport_auth.rate_limit import AsyncMinDelayLimiter

FIXTURES = Path(__file__).parent.parent / "fixtures"

_AM_URL = f"{PASSPORT_URL}/am?app_platform=android"
_MULTISTEP_URL = f"{PASSPORT_BFF_URL}/auth/multistep_start"
_SUBMIT_URL = f"{PASSPORT_BFF_URL}/auth/password/submit"
_STATUS_URL = f"{PASSPORT_URL}/auth/new/magic/status/"

_TEST_TRACK_ID = "test-track-id-0123456789"
_TEST_PAGE_CSRF_INPUT = "test-csrf-input-attr-01234567890"
_TEST_SUBMIT_CSRF = "test-submit-csrf-abcdef0123456789"

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
                _MULTISTEP_URL,
                status=200,
                payload={"track_id": _TEST_TRACK_ID},
                headers=_JSON_CT,
            )
            m.post(
                _SUBMIT_URL,
                status=200,
                payload={"csrf_token": _TEST_SUBMIT_CSRF},
                headers=_JSON_CT,
            )
            qr = await flow.get_qr()

            # Verify the extracted page CSRF was sent as X-CSRF-Token on
            # both BFF calls (multistep_start and password/submit).
            multistep_calls = m.requests[("POST", URL(_MULTISTEP_URL))]
            submit_calls = m.requests[("POST", URL(_SUBMIT_URL))]
            assert multistep_calls[0].kwargs["headers"]["X-CSRF-Token"] == expected_csrf
            assert submit_calls[0].kwargs["headers"]["X-CSRF-Token"] == expected_csrf

        assert qr.track_id == _TEST_TRACK_ID
        # The per-track csrf_token returned by submit is what the poll
        # endpoint consumes — not the page CSRF.
        assert qr.csrf_token == _TEST_SUBMIT_CSRF

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
                _MULTISTEP_URL,
                status=200,
                payload={
                    "track_id": _TEST_TRACK_ID,
                    "auth_methods": ["password", "magic_x_token"],
                },
                headers=_JSON_CT,
            )
            m.post(
                _SUBMIT_URL,
                status=200,
                payload={
                    "track_id": _TEST_TRACK_ID,
                    "csrf_token": _TEST_SUBMIT_CSRF,
                    "user_code": "1234567890",
                    "expires_in": 300,
                },
                headers=_JSON_CT,
            )
            qr = await flow.get_qr()

        assert isinstance(qr, QrSession)
        assert qr.track_id == _TEST_TRACK_ID
        assert qr.csrf_token == _TEST_SUBMIT_CSRF
        assert f"track_id={_TEST_TRACK_ID}" in qr.qr_url

    async def test_multistep_missing_track_id_raises(self, flow: QrLoginFlow) -> None:
        html = (FIXTURES / "csrf_input_attr.html").read_text()
        with aioresponses() as m:
            m.get(_AM_URL, status=200, body=html, headers=_HTML_CT)
            m.post(
                _MULTISTEP_URL,
                status=200,
                payload={"auth_methods": ["password"]},
                headers=_JSON_CT,
            )
            with pytest.raises(AuthFailedError):
                await flow.get_qr()

    async def test_submit_status_error_raises(self, flow: QrLoginFlow) -> None:
        html = (FIXTURES / "csrf_input_attr.html").read_text()
        with aioresponses() as m:
            m.get(_AM_URL, status=200, body=html, headers=_HTML_CT)
            m.post(
                _MULTISTEP_URL,
                status=200,
                payload={"track_id": _TEST_TRACK_ID},
                headers=_JSON_CT,
            )
            m.post(
                _SUBMIT_URL,
                status=200,
                payload={"status": "error", "errors": ["captcha"]},
                headers=_JSON_CT,
            )
            with pytest.raises(AuthFailedError, match="status='error'"):
                await flow.get_qr()

    async def test_submit_unexpected_status_raises(self, flow: QrLoginFlow) -> None:
        """Non-ok status like 'captcha' must not fall through to csrf_token check."""
        html = (FIXTURES / "csrf_input_attr.html").read_text()
        with aioresponses() as m:
            m.get(_AM_URL, status=200, body=html, headers=_HTML_CT)
            m.post(
                _MULTISTEP_URL,
                status=200,
                payload={"track_id": _TEST_TRACK_ID},
                headers=_JSON_CT,
            )
            m.post(
                _SUBMIT_URL,
                status=200,
                payload={"status": "captcha", "captcha_url": "https://example.com/c"},
                headers=_JSON_CT,
            )
            with pytest.raises(AuthFailedError, match="status='captcha'"):
                await flow.get_qr()

    async def test_submit_missing_csrf_raises(self, flow: QrLoginFlow) -> None:
        html = (FIXTURES / "csrf_input_attr.html").read_text()
        with aioresponses() as m:
            m.get(_AM_URL, status=200, body=html, headers=_HTML_CT)
            m.post(
                _MULTISTEP_URL,
                status=200,
                payload={"track_id": _TEST_TRACK_ID},
                headers=_JSON_CT,
            )
            m.post(
                _SUBMIT_URL,
                status=200,
                payload={"track_id": _TEST_TRACK_ID},
                headers=_JSON_CT,
            )
            with pytest.raises(AuthFailedError):
                await flow.get_qr()


# ------------------------------------------------------------------ #
# QR status check
# ------------------------------------------------------------------ #
class TestCheckStatus:
    async def test_pending(self, flow: QrLoginFlow) -> None:
        qr = QrSession(track_id=_TEST_TRACK_ID, csrf_token=_TEST_SUBMIT_CSRF, qr_url="http://x")
        with aioresponses() as m:
            m.post(
                _STATUS_URL,
                status=200,
                payload={"status": "pending"},
                headers=_JSON_CT,
            )
            assert await flow.check_status(qr) is False

    async def test_ok(self, flow: QrLoginFlow) -> None:
        qr = QrSession(track_id=_TEST_TRACK_ID, csrf_token=_TEST_SUBMIT_CSRF, qr_url="http://x")
        with aioresponses() as m:
            m.post(
                _STATUS_URL,
                status=200,
                payload={"status": "ok"},
                headers=_JSON_CT,
            )
            assert await flow.check_status(qr) is True
