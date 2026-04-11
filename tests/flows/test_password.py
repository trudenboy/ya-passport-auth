"""Tests for the password login flow.

Covers multi-step auth start, password submission, SMS, magic link,
captcha, and error handling.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from pathlib import Path

import aiohttp
import pytest
from aioresponses import aioresponses

from ya_passport_auth.config import ClientConfig
from ya_passport_auth.constants import PASSPORT_LEGACY_URL, PASSPORT_URL
from ya_passport_auth.exceptions import (
    AccountNotFoundError,
    AuthFailedError,
    CaptchaRequiredError,
    PasswordError,
)
from ya_passport_auth.flows.password import PasswordLoginFlow
from ya_passport_auth.http import SafeHttpClient
from ya_passport_auth.models import AuthSession, CaptchaChallenge
from ya_passport_auth.rate_limit import AsyncMinDelayLimiter

FIXTURES = Path(__file__).parent.parent / "fixtures"

_AM_URL = f"{PASSPORT_URL}/am?app_platform=android"
_START_URL = f"{PASSPORT_LEGACY_URL}/auth/multi_step/start"
_PASSWORD_URL = f"{PASSPORT_LEGACY_URL}/auth/multi_step/commit_password"
_SMS_REQUEST_URL = f"{PASSPORT_LEGACY_URL}/phone-confirm-code-submit"
_SMS_VERIFY_URL = f"{PASSPORT_LEGACY_URL}/phone-confirm-code"
_SMS_COMMIT_URL = f"{PASSPORT_LEGACY_URL}/multi-step-commit-sms-code"
_MAGIC_SEND_URL = f"{PASSPORT_LEGACY_URL}/auth/send_magic_letter"
_MAGIC_STATUS_URL = f"{PASSPORT_URL}/auth/letter/status/"
_CAPTCHA_GET_URL = f"{PASSPORT_LEGACY_URL}/textcaptcha"
_CAPTCHA_CHECK_URL = f"{PASSPORT_LEGACY_URL}/checkHuman"

_HTML_CT = {"Content-Type": "text/html; charset=utf-8"}
_JSON_CT = {"Content-Type": "application/json"}

_TEST_TRACK_ID = "test-track-pwd-0123456789"
_TEST_CSRF = "test-csrf-input-attr-01234567890"


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
def flow(http: SafeHttpClient) -> PasswordLoginFlow:
    return PasswordLoginFlow(http=http)


@pytest.fixture
def auth_session() -> AuthSession:
    return AuthSession(
        track_id=_TEST_TRACK_ID,
        csrf_token=_TEST_CSRF,
        auth_methods=("password", "magic_x_token"),
    )


def _csrf_html() -> str:
    return (FIXTURES / "csrf_input_attr.html").read_text()


# ------------------------------------------------------------------ #
# start_auth
# ------------------------------------------------------------------ #
class TestStartAuth:
    async def test_success(self, flow: PasswordLoginFlow) -> None:
        with aioresponses() as m:
            m.get(_AM_URL, status=200, body=_csrf_html(), headers=_HTML_CT)
            m.post(
                _START_URL,
                status=200,
                payload={
                    "status": "ok",
                    "can_authorize": True,
                    "track_id": _TEST_TRACK_ID,
                    "auth_methods": ["password", "magic_x_token", "sms"],
                    "magic_link_email": "u***@example.com",
                },
                headers=_JSON_CT,
            )
            auth = await flow.start_auth("testuser")

        assert isinstance(auth, AuthSession)
        assert auth.track_id == _TEST_TRACK_ID
        assert auth.auth_methods == ("password", "magic_x_token", "sms")
        assert auth.magic_link_email == "u***@example.com"

    async def test_account_not_found(self, flow: PasswordLoginFlow) -> None:
        with aioresponses() as m:
            m.get(_AM_URL, status=200, body=_csrf_html(), headers=_HTML_CT)
            m.post(
                _START_URL,
                status=200,
                payload={
                    "status": "ok",
                    "can_authorize": False,
                    "can_register": True,
                    "track_id": _TEST_TRACK_ID,
                },
                headers=_JSON_CT,
            )
            with pytest.raises(AccountNotFoundError, match="cannot authorize"):
                await flow.start_auth("nonexistent")

    async def test_missing_track_id(self, flow: PasswordLoginFlow) -> None:
        with aioresponses() as m:
            m.get(_AM_URL, status=200, body=_csrf_html(), headers=_HTML_CT)
            m.post(
                _START_URL,
                status=200,
                payload={
                    "status": "ok",
                    "can_authorize": True,
                    "auth_methods": ["password"],
                },
                headers=_JSON_CT,
            )
            with pytest.raises(AuthFailedError, match="track_id"):
                await flow.start_auth("testuser")

    async def test_error_status(self, flow: PasswordLoginFlow) -> None:
        with aioresponses() as m:
            m.get(_AM_URL, status=200, body=_csrf_html(), headers=_HTML_CT)
            m.post(
                _START_URL,
                status=200,
                payload={"status": "error", "errors": ["rate_limit"]},
                headers=_JSON_CT,
            )
            with pytest.raises(AuthFailedError, match="status='error'"):
                await flow.start_auth("testuser")

    async def test_no_auth_methods(self, flow: PasswordLoginFlow) -> None:
        """When auth_methods is absent, tuple should be empty."""
        with aioresponses() as m:
            m.get(_AM_URL, status=200, body=_csrf_html(), headers=_HTML_CT)
            m.post(
                _START_URL,
                status=200,
                payload={
                    "status": "ok",
                    "can_authorize": True,
                    "track_id": _TEST_TRACK_ID,
                },
                headers=_JSON_CT,
            )
            auth = await flow.start_auth("testuser")
        assert auth.auth_methods == ()


# ------------------------------------------------------------------ #
# submit_password
# ------------------------------------------------------------------ #
class TestSubmitPassword:
    async def test_success(self, flow: PasswordLoginFlow, auth_session: AuthSession) -> None:
        with aioresponses() as m:
            m.post(
                _PASSWORD_URL,
                status=200,
                payload={"status": "ok"},
                headers=_JSON_CT,
            )
            await flow.submit_password(auth_session, "correctpass")

    async def test_wrong_password(self, flow: PasswordLoginFlow, auth_session: AuthSession) -> None:
        with aioresponses() as m:
            m.post(
                _PASSWORD_URL,
                status=200,
                payload={
                    "status": "error",
                    "errors": ["password.not_matched"],
                },
                headers=_JSON_CT,
            )
            with pytest.raises(PasswordError, match="wrong password"):
                await flow.submit_password(auth_session, "wrongpass")

    async def test_captcha_required(
        self, flow: PasswordLoginFlow, auth_session: AuthSession
    ) -> None:
        with aioresponses() as m:
            m.post(
                _PASSWORD_URL,
                status=200,
                payload={
                    "status": "error",
                    "errors": ["captcha.required"],
                },
                headers=_JSON_CT,
            )
            with pytest.raises(CaptchaRequiredError, match="captcha"):
                await flow.submit_password(auth_session, "anypass")

    async def test_redirect_raises(
        self, flow: PasswordLoginFlow, auth_session: AuthSession
    ) -> None:
        with aioresponses() as m:
            m.post(
                _PASSWORD_URL,
                status=200,
                payload={
                    "status": "redirect",
                    "redirect_url": "https://evil.example.com",
                },
                headers=_JSON_CT,
            )
            with pytest.raises(AuthFailedError, match="redirect"):
                await flow.submit_password(auth_session, "anypass")

    async def test_unknown_error(self, flow: PasswordLoginFlow, auth_session: AuthSession) -> None:
        with aioresponses() as m:
            m.post(
                _PASSWORD_URL,
                status=200,
                payload={"status": "unknown_state"},
                headers=_JSON_CT,
            )
            with pytest.raises(AuthFailedError, match="status='unknown_state'"):
                await flow.submit_password(auth_session, "anypass")


# ------------------------------------------------------------------ #
# SMS flow
# ------------------------------------------------------------------ #
class TestSmsFlow:
    async def test_request_sms_success(
        self, flow: PasswordLoginFlow, auth_session: AuthSession
    ) -> None:
        with aioresponses() as m:
            m.post(
                _SMS_REQUEST_URL,
                status=200,
                payload={"status": "ok"},
                headers=_JSON_CT,
            )
            await flow.request_sms(auth_session)

    async def test_request_sms_error(
        self, flow: PasswordLoginFlow, auth_session: AuthSession
    ) -> None:
        with aioresponses() as m:
            m.post(
                _SMS_REQUEST_URL,
                status=200,
                payload={"status": "error"},
                headers=_JSON_CT,
            )
            with pytest.raises(AuthFailedError, match="SMS request"):
                await flow.request_sms(auth_session)

    async def test_submit_sms_success(
        self, flow: PasswordLoginFlow, auth_session: AuthSession
    ) -> None:
        with aioresponses() as m:
            m.post(
                _SMS_VERIFY_URL,
                status=200,
                payload={"status": "ok"},
                headers=_JSON_CT,
            )
            m.post(
                _SMS_COMMIT_URL,
                status=200,
                payload={"status": "ok"},
                headers=_JSON_CT,
            )
            await flow.submit_sms(auth_session, "123456")

    async def test_submit_sms_verify_fails(
        self, flow: PasswordLoginFlow, auth_session: AuthSession
    ) -> None:
        with aioresponses() as m:
            m.post(
                _SMS_VERIFY_URL,
                status=200,
                payload={"status": "error", "errors": ["code.invalid"]},
                headers=_JSON_CT,
            )
            with pytest.raises(AuthFailedError, match="verification failed"):
                await flow.submit_sms(auth_session, "000000")

    async def test_submit_sms_commit_fails(
        self, flow: PasswordLoginFlow, auth_session: AuthSession
    ) -> None:
        with aioresponses() as m:
            m.post(
                _SMS_VERIFY_URL,
                status=200,
                payload={"status": "ok"},
                headers=_JSON_CT,
            )
            m.post(
                _SMS_COMMIT_URL,
                status=200,
                payload={"status": "error"},
                headers=_JSON_CT,
            )
            with pytest.raises(AuthFailedError, match="SMS commit"):
                await flow.submit_sms(auth_session, "123456")


# ------------------------------------------------------------------ #
# Magic link flow
# ------------------------------------------------------------------ #
class TestMagicLinkFlow:
    async def test_request_magic_link(
        self, flow: PasswordLoginFlow, auth_session: AuthSession
    ) -> None:
        with aioresponses() as m:
            m.post(
                _MAGIC_SEND_URL,
                status=200,
                payload={"status": "ok"},
                headers=_JSON_CT,
            )
            await flow.request_magic_link(auth_session)

    async def test_request_magic_link_error(
        self, flow: PasswordLoginFlow, auth_session: AuthSession
    ) -> None:
        with aioresponses() as m:
            m.post(
                _MAGIC_SEND_URL,
                status=200,
                payload={"status": "error"},
                headers=_JSON_CT,
            )
            with pytest.raises(AuthFailedError, match="magic link"):
                await flow.request_magic_link(auth_session)

    async def test_check_pending(self, flow: PasswordLoginFlow, auth_session: AuthSession) -> None:
        with aioresponses() as m:
            m.post(
                _MAGIC_STATUS_URL,
                status=200,
                payload={"status": "pending"},
                headers=_JSON_CT,
            )
            assert await flow.check_magic_link(auth_session) is False

    async def test_check_confirmed(
        self, flow: PasswordLoginFlow, auth_session: AuthSession
    ) -> None:
        with aioresponses() as m:
            m.post(
                _MAGIC_STATUS_URL,
                status=200,
                payload={"status": "magic_link_confirmed"},
                headers=_JSON_CT,
            )
            assert await flow.check_magic_link(auth_session) is True


# ------------------------------------------------------------------ #
# Captcha flow
# ------------------------------------------------------------------ #
class TestCaptchaFlow:
    async def test_get_captcha(self, flow: PasswordLoginFlow, auth_session: AuthSession) -> None:
        with aioresponses() as m:
            m.post(
                _CAPTCHA_GET_URL,
                status=200,
                payload={
                    "captcha_url": "https://captcha.yandex.net/image?key=abc",
                    "key": "captcha-key-123",
                },
                headers=_JSON_CT,
            )
            challenge = await flow.get_captcha(auth_session)
        assert isinstance(challenge, CaptchaChallenge)
        assert challenge.image_url == "https://captcha.yandex.net/image?key=abc"
        assert challenge.key == "captcha-key-123"

    async def test_get_captcha_missing_fields(
        self, flow: PasswordLoginFlow, auth_session: AuthSession
    ) -> None:
        with aioresponses() as m:
            m.post(
                _CAPTCHA_GET_URL,
                status=200,
                payload={"status": "ok"},
                headers=_JSON_CT,
            )
            with pytest.raises(AuthFailedError, match="captcha_url or key"):
                await flow.get_captcha(auth_session)

    async def test_submit_captcha_correct(
        self, flow: PasswordLoginFlow, auth_session: AuthSession
    ) -> None:
        challenge = CaptchaChallenge(
            image_url="https://captcha.yandex.net/image",
            key="captcha-key-123",
        )
        with aioresponses() as m:
            m.post(
                _CAPTCHA_CHECK_URL,
                status=200,
                payload={"status": "ok"},
                headers=_JSON_CT,
            )
            assert await flow.submit_captcha(auth_session, challenge, "answer") is True

    async def test_submit_captcha_wrong(
        self, flow: PasswordLoginFlow, auth_session: AuthSession
    ) -> None:
        challenge = CaptchaChallenge(
            image_url="https://captcha.yandex.net/image",
            key="captcha-key-123",
        )
        with aioresponses() as m:
            m.post(
                _CAPTCHA_CHECK_URL,
                status=200,
                payload={"status": "failed"},
                headers=_JSON_CT,
            )
            assert await flow.submit_captcha(auth_session, challenge, "wrong") is False
