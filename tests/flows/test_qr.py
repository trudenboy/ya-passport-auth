"""Tests for the QR login flow.

Covers CSRF extraction (5 pattern variants + missing), QR session
creation against the ``/pwl-yandex`` BFF, and QR status polling
including the ``sessions/get_session`` follow-up. Token exchange
tests live in ``test_token_exchange.py``.
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

_AM_URL = f"{PASSPORT_URL}/pwl-yandex"
_SUBMIT_URL = f"{PASSPORT_BFF_URL}/auth/password/submit"
_MAGIC_CODE_URL = f"{PASSPORT_BFF_URL}/auth/magic/code"
_STATUS_URL = f"{PASSPORT_BFF_URL}/auth/magic/code/status"
_GET_SESSION_URL = f"{PASSPORT_BFF_URL}/sessions/get_session"

_TEST_TRACK_ID = "test-track-id-0123456789"
_TEST_SESSION_TRACK_ID = "test-session-track-id-9876543210"
_TEST_PAGE_CSRF_INPUT = "test-csrf-input-attr-01234567890"
_TEST_QR_LINK = f"{PASSPORT_URL}/auth/magic/code/?track_id={_TEST_TRACK_ID}"

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
def flow(
    http: SafeHttpClient,
    session: aiohttp.ClientSession,
    config: ClientConfig,
) -> QrLoginFlow:
    return QrLoginFlow(http=http, session=session, config=config)


def _submit_payload(track_id: str = _TEST_TRACK_ID) -> dict[str, object]:
    """Realistic password/submit response shape (server returns more fields)."""
    return {
        "track_id": track_id,
        "status": "ok",
        "csrf_token": "server-side-per-track-token-not-used-by-client",
    }


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
            ("csrf_bare_global.html", "test-csrf-bare-global-0123456789"),
        ],
    )
    async def test_csrf_patterns(
        self, flow: QrLoginFlow, fixture_file: str, expected_csrf: str
    ) -> None:
        html = (FIXTURES / fixture_file).read_text()
        with aioresponses() as m:
            m.get(_AM_URL, status=200, body=html, headers=_HTML_CT)
            m.post(_SUBMIT_URL, status=200, payload=_submit_payload(), headers=_JSON_CT)
            m.post(
                _MAGIC_CODE_URL,
                status=200,
                payload={"link": _TEST_QR_LINK},
                headers=_JSON_CT,
            )
            qr = await flow.get_qr()

            # Page CSRF must propagate as X-CSRF-Token on BOTH BFF calls.
            submit_calls = m.requests[("POST", URL(_SUBMIT_URL))]
            magic_calls = m.requests[("POST", URL(_MAGIC_CODE_URL))]
            assert submit_calls[0].kwargs["headers"]["X-CSRF-Token"] == expected_csrf
            assert magic_calls[0].kwargs["headers"]["X-CSRF-Token"] == expected_csrf

        assert qr.track_id == _TEST_TRACK_ID
        # The page-level CSRF is what poll requests will carry in the header.
        assert qr.csrf_token == expected_csrf
        assert qr.qr_url == _TEST_QR_LINK

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
            m.post(_SUBMIT_URL, status=200, payload=_submit_payload(), headers=_JSON_CT)
            m.post(
                _MAGIC_CODE_URL,
                status=200,
                payload={"link": _TEST_QR_LINK},
                headers=_JSON_CT,
            )
            qr = await flow.get_qr()

        assert isinstance(qr, QrSession)
        assert qr.track_id == _TEST_TRACK_ID
        assert qr.csrf_token == _TEST_PAGE_CSRF_INPUT
        assert qr.qr_url == _TEST_QR_LINK
        # auth_state preserves the full submit response so polling can replay it.
        state_dict = dict(qr.auth_state)
        assert state_dict["track_id"] == _TEST_TRACK_ID
        assert state_dict["status"] == "ok"

    async def test_submit_sends_json_body(self, flow: QrLoginFlow) -> None:
        html = (FIXTURES / "csrf_input_attr.html").read_text()
        with aioresponses() as m:
            m.get(_AM_URL, status=200, body=html, headers=_HTML_CT)
            m.post(_SUBMIT_URL, status=200, payload=_submit_payload(), headers=_JSON_CT)
            m.post(
                _MAGIC_CODE_URL,
                status=200,
                payload={"link": _TEST_QR_LINK},
                headers=_JSON_CT,
            )
            await flow.get_qr()

            submit_calls = m.requests[("POST", URL(_SUBMIT_URL))]
            # password/submit must send JSON body containing retpath
            # (aioresponses preserves the json= kwarg verbatim).
            assert submit_calls[0].kwargs["json"] == {"retpath": f"{PASSPORT_URL}/profile"}
            assert submit_calls[0].kwargs["data"] is None

    async def test_magic_code_sends_form_data(self, flow: QrLoginFlow) -> None:
        html = (FIXTURES / "csrf_input_attr.html").read_text()
        with aioresponses() as m:
            m.get(_AM_URL, status=200, body=html, headers=_HTML_CT)
            m.post(_SUBMIT_URL, status=200, payload=_submit_payload(), headers=_JSON_CT)
            m.post(
                _MAGIC_CODE_URL,
                status=200,
                payload={"link": _TEST_QR_LINK},
                headers=_JSON_CT,
            )
            await flow.get_qr()

            magic_calls = m.requests[("POST", URL(_MAGIC_CODE_URL))]
            assert magic_calls[0].kwargs["data"] == {
                "location_id": "0",
                "magic_track_id": _TEST_TRACK_ID,
                "track_id": "",
            }
            assert magic_calls[0].kwargs["json"] is None

    async def test_submit_missing_track_id_raises(self, flow: QrLoginFlow) -> None:
        html = (FIXTURES / "csrf_input_attr.html").read_text()
        with aioresponses() as m:
            m.get(_AM_URL, status=200, body=html, headers=_HTML_CT)
            m.post(_SUBMIT_URL, status=200, payload={"status": "ok"}, headers=_JSON_CT)
            with pytest.raises(AuthFailedError, match="track_id"):
                await flow.get_qr()

    async def test_submit_empty_track_id_raises(self, flow: QrLoginFlow) -> None:
        html = (FIXTURES / "csrf_input_attr.html").read_text()
        with aioresponses() as m:
            m.get(_AM_URL, status=200, body=html, headers=_HTML_CT)
            m.post(
                _SUBMIT_URL,
                status=200,
                payload={"track_id": "   "},
                headers=_JSON_CT,
            )
            with pytest.raises(AuthFailedError, match="track_id"):
                await flow.get_qr()

    async def test_magic_code_missing_link_raises(self, flow: QrLoginFlow) -> None:
        html = (FIXTURES / "csrf_input_attr.html").read_text()
        with aioresponses() as m:
            m.get(_AM_URL, status=200, body=html, headers=_HTML_CT)
            m.post(_SUBMIT_URL, status=200, payload=_submit_payload(), headers=_JSON_CT)
            m.post(_MAGIC_CODE_URL, status=200, payload={}, headers=_JSON_CT)
            with pytest.raises(AuthFailedError, match="link"):
                await flow.get_qr()

    async def test_link_with_disallowed_host_raises(self, flow: QrLoginFlow) -> None:
        """A malicious server response substituting a phishing URL must be rejected."""
        html = (FIXTURES / "csrf_input_attr.html").read_text()
        with aioresponses() as m:
            m.get(_AM_URL, status=200, body=html, headers=_HTML_CT)
            m.post(_SUBMIT_URL, status=200, payload=_submit_payload(), headers=_JSON_CT)
            m.post(
                _MAGIC_CODE_URL,
                status=200,
                payload={"link": "https://evil.example.com/phish"},
                headers=_JSON_CT,
            )
            with pytest.raises(AuthFailedError, match="allow-list"):
                await flow.get_qr()

    async def test_link_with_non_https_scheme_raises(self, flow: QrLoginFlow) -> None:
        html = (FIXTURES / "csrf_input_attr.html").read_text()
        with aioresponses() as m:
            m.get(_AM_URL, status=200, body=html, headers=_HTML_CT)
            m.post(_SUBMIT_URL, status=200, payload=_submit_payload(), headers=_JSON_CT)
            m.post(
                _MAGIC_CODE_URL,
                status=200,
                payload={"link": "http://passport.yandex.ru/insecure"},
                headers=_JSON_CT,
            )
            with pytest.raises(AuthFailedError, match="non-HTTPS"):
                await flow.get_qr()


# ------------------------------------------------------------------ #
# QR status check
# ------------------------------------------------------------------ #
class TestCheckStatus:
    def _make_qr(self) -> QrSession:
        return QrSession(
            track_id=_TEST_TRACK_ID,
            csrf_token=_TEST_PAGE_CSRF_INPUT,
            qr_url=_TEST_QR_LINK,
            auth_state=tuple(_submit_payload().items()),
        )

    async def test_pending(self, flow: QrLoginFlow) -> None:
        qr = self._make_qr()
        with aioresponses() as m:
            m.post(
                _STATUS_URL,
                status=200,
                payload={"state": "auth_wait_user_action"},
                headers=_JSON_CT,
            )
            assert await flow.check_status(qr) is False

    async def test_ok_triggers_get_session(self, flow: QrLoginFlow) -> None:
        qr = self._make_qr()
        with aioresponses() as m:
            m.post(
                _STATUS_URL,
                status=200,
                payload={
                    "state": "otp_auth_finished",
                    "trackId": _TEST_SESSION_TRACK_ID,
                },
                headers=_JSON_CT,
            )
            m.post(_GET_SESSION_URL, status=200, payload={"status": "ok"}, headers=_JSON_CT)
            assert await flow.check_status(qr) is True

            status_calls = m.requests[("POST", URL(_STATUS_URL))]
            get_session_calls = m.requests[("POST", URL(_GET_SESSION_URL))]
            # check_status forwards the full auth_state as JSON.
            assert status_calls[0].kwargs["json"] == dict(_submit_payload().items())
            assert status_calls[0].kwargs["headers"]["X-CSRF-Token"] == _TEST_PAGE_CSRF_INPUT
            # get_session uses the session-scope trackId from the status response.
            assert get_session_calls[0].kwargs["data"] == {"track_id": _TEST_SESSION_TRACK_ID}

    async def test_ok_missing_track_id_raises(self, flow: QrLoginFlow) -> None:
        qr = self._make_qr()
        with aioresponses() as m:
            m.post(
                _STATUS_URL,
                status=200,
                payload={"state": "otp_auth_finished"},
                headers=_JSON_CT,
            )
            with pytest.raises(AuthFailedError, match="trackId"):
                await flow.check_status(qr)

    async def test_empty_auth_state_raises(self, flow: QrLoginFlow) -> None:
        """A QrSession constructed without auth_state cannot poll — fail fast."""
        qr = QrSession(
            track_id=_TEST_TRACK_ID,
            csrf_token=_TEST_PAGE_CSRF_INPUT,
            qr_url=_TEST_QR_LINK,
        )
        with pytest.raises(AuthFailedError, match="empty auth_state"):
            await flow.check_status(qr)

    async def test_empty_body_treated_as_pending(self, flow: QrLoginFlow) -> None:
        # Passport returns `{}` while the QR is unscanned — the normal
        # pending signal, not a malformed response.
        qr = self._make_qr()
        with aioresponses() as m:
            m.post(_STATUS_URL, status=200, payload={}, headers=_JSON_CT)
            assert await flow.check_status(qr) is False

    async def test_empty_state_treated_as_pending(self, flow: QrLoginFlow) -> None:
        qr = self._make_qr()
        with aioresponses() as m:
            m.post(_STATUS_URL, status=200, payload={"state": ""}, headers=_JSON_CT)
            assert await flow.check_status(qr) is False


# ------------------------------------------------------------------ #
# QrSession redaction
# ------------------------------------------------------------------ #
class TestQrSessionRepr:
    def test_repr_redacts_csrf_and_auth_state(self) -> None:
        qr = QrSession(
            track_id="visible-track-id",
            csrf_token="SUPER-SECRET-CSRF",
            qr_url="https://passport.yandex.ru/auth/magic/code/?track_id=visible",
            auth_state=(("server_token", "SUPER-SECRET-SERVER-TOKEN"),),
        )
        r = repr(qr)
        assert "SUPER-SECRET-CSRF" not in r
        assert "SUPER-SECRET-SERVER-TOKEN" not in r
        # Non-secret fields are visible for debugging.
        assert "visible-track-id" in r
        assert "visible" in r
