"""Integration tests for password and cookie auth via PassportClient."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from pathlib import Path

import pytest
from aioresponses import aioresponses
from yarl import URL

from ya_passport_auth.client import PassportClient
from ya_passport_auth.config import ClientConfig
from ya_passport_auth.constants import (
    MUSIC_TOKEN_URL,
    PASSPORT_API_URL,
    PASSPORT_LEGACY_URL,
    PASSPORT_URL,
)
from ya_passport_auth.credentials import Credentials
from ya_passport_auth.exceptions import (
    AccountNotFoundError,
    AuthFailedError,
    CaptchaRequiredError,
    PasswordError,
)
from ya_passport_auth.models import AuthSession, CaptchaChallenge

FIXTURES = Path(__file__).parent.parent / "fixtures"

_AM_URL = f"{PASSPORT_URL}/am?app_platform=android"
_START_URL = f"{PASSPORT_LEGACY_URL}/auth/multi_step/start"
_PASSWORD_URL = f"{PASSPORT_LEGACY_URL}/auth/multi_step/commit_password"
_SMS_REQUEST_URL = f"{PASSPORT_LEGACY_URL}/phone-confirm-code-submit"
_SMS_VERIFY_URL = f"{PASSPORT_LEGACY_URL}/phone-confirm-code"
_SMS_COMMIT_URL = f"{PASSPORT_LEGACY_URL}/multi-step-commit-sms-code"
_MAGIC_SEND_URL = f"{PASSPORT_LEGACY_URL}/auth/send_magic_letter"
_MAGIC_STATUS_URL = f"{PASSPORT_URL}/auth/letter/status/"
_TOKEN_URL = f"{PASSPORT_API_URL}/1/bundle/oauth/token_by_sessionid"
_ACCOUNT_URL = f"{PASSPORT_API_URL}/1/bundle/account/short_info/?avatar_size=islands-300"

_HTML_CT = {"Content-Type": "text/html; charset=utf-8"}
_JSON_CT = {"Content-Type": "application/json"}

_TEST_TRACK_ID = "test-track-int-0123456789"
_TEST_CSRF = "test-csrf-input-attr-01234567890"
_TEST_X_TOKEN = "test-xtoken-int-0123456789abcdef"
_TEST_MUSIC_TOKEN = "test-musictoken-int-fedcba9876543210"


@pytest.fixture
def config() -> ClientConfig:
    return ClientConfig(min_request_interval_seconds=0.001)


@pytest.fixture
async def client(config: ClientConfig) -> AsyncGenerator[PassportClient, None]:
    async with PassportClient.create(config=config) as c:
        yield c


def _csrf_html() -> str:
    return (FIXTURES / "csrf_input_attr.html").read_text()


def _mock_token_exchange(m: aioresponses) -> None:
    """Mock cookies→x_token and x_token→music_token exchange."""
    m.post(
        _TOKEN_URL,
        status=200,
        payload={"access_token": _TEST_X_TOKEN},
        headers=_JSON_CT,
    )
    m.post(
        MUSIC_TOKEN_URL,
        status=200,
        payload={"access_token": _TEST_MUSIC_TOKEN},
        headers=_JSON_CT,
    )
    m.get(
        _ACCOUNT_URL,
        status=200,
        payload={"uid": 12345, "display_login": "testuser"},
        headers=_JSON_CT,
    )


def _seed_session_cookies(client: PassportClient) -> None:
    """Pre-populate the internal session jar with Yandex cookies.

    In production, these would be set by the ``commit_password`` /
    ``sms_commit`` / ``magic_link`` responses via ``Set-Cookie`` headers.
    ``aioresponses`` does not process ``Set-Cookie``, so we inject them.
    """
    client._session.cookie_jar.update_cookies(
        {"Session_id": "test-session-id", "sessionid2": "test-session-id2"},
        response_url=URL(PASSPORT_URL),
    )


class TestStartPasswordAuth:
    async def test_returns_auth_session(self, client: PassportClient) -> None:
        with aioresponses() as m:
            m.get(_AM_URL, status=200, body=_csrf_html(), headers=_HTML_CT)
            m.post(
                _START_URL,
                status=200,
                payload={
                    "status": "ok",
                    "can_authorize": True,
                    "track_id": _TEST_TRACK_ID,
                    "auth_methods": ["password", "magic_x_token"],
                },
                headers=_JSON_CT,
            )
            auth = await client.start_password_auth("testuser")

        assert isinstance(auth, AuthSession)
        assert auth.track_id == _TEST_TRACK_ID

    async def test_account_not_found(self, client: PassportClient) -> None:
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
            with pytest.raises(AccountNotFoundError):
                await client.start_password_auth("nonexistent")


class TestLoginPassword:
    async def test_full_flow(self, client: PassportClient) -> None:
        auth = AuthSession(
            track_id=_TEST_TRACK_ID,
            csrf_token=_TEST_CSRF,
            auth_methods=("password",),
        )
        with aioresponses() as m:
            m.post(
                _PASSWORD_URL,
                status=200,
                payload={"status": "ok"},
                headers=_JSON_CT,
            )
            _mock_token_exchange(m)
            _seed_session_cookies(client)
            creds = await client.login_password(auth, "correctpass")

        assert isinstance(creds, Credentials)
        assert creds.x_token.get_secret() == _TEST_X_TOKEN
        assert creds.music_token is not None
        assert creds.music_token.get_secret() == _TEST_MUSIC_TOKEN

    async def test_wrong_password(self, client: PassportClient) -> None:
        auth = AuthSession(
            track_id=_TEST_TRACK_ID,
            csrf_token=_TEST_CSRF,
            auth_methods=("password",),
        )
        with aioresponses() as m:
            m.post(
                _PASSWORD_URL,
                status=200,
                payload={"status": "error", "errors": ["password.not_matched"]},
                headers=_JSON_CT,
            )
            with pytest.raises(PasswordError):
                await client.login_password(auth, "wrongpass")

    async def test_captcha_required(self, client: PassportClient) -> None:
        auth = AuthSession(
            track_id=_TEST_TRACK_ID,
            csrf_token=_TEST_CSRF,
            auth_methods=("password",),
        )
        with aioresponses() as m:
            m.post(
                _PASSWORD_URL,
                status=200,
                payload={"status": "error", "errors": ["captcha.required"]},
                headers=_JSON_CT,
            )
            with pytest.raises(CaptchaRequiredError):
                await client.login_password(auth, "anypass")


class TestLoginSms:
    async def test_full_flow(self, client: PassportClient) -> None:
        auth = AuthSession(
            track_id=_TEST_TRACK_ID,
            csrf_token=_TEST_CSRF,
            auth_methods=("sms",),
        )
        with aioresponses() as m:
            m.post(_SMS_REQUEST_URL, status=200, payload={"status": "ok"}, headers=_JSON_CT)
            await client.request_sms(auth)

            m.post(_SMS_VERIFY_URL, status=200, payload={"status": "ok"}, headers=_JSON_CT)
            m.post(_SMS_COMMIT_URL, status=200, payload={"status": "ok"}, headers=_JSON_CT)
            _mock_token_exchange(m)
            _seed_session_cookies(client)
            creds = await client.login_sms(auth, "123456")

        assert isinstance(creds, Credentials)
        assert creds.x_token.get_secret() == _TEST_X_TOKEN


class TestMagicLinkAuth:
    async def test_check_magic_link(self, client: PassportClient) -> None:
        auth = AuthSession(
            track_id=_TEST_TRACK_ID,
            csrf_token=_TEST_CSRF,
            auth_methods=("magic_x_token",),
        )
        with aioresponses() as m:
            m.post(_MAGIC_SEND_URL, status=200, payload={"status": "ok"}, headers=_JSON_CT)
            await client.request_magic_link(auth)

            m.post(
                _MAGIC_STATUS_URL,
                status=200,
                payload={"status": "pending"},
                headers=_JSON_CT,
            )
            assert await client.check_magic_link(auth) is False

    async def test_poll_magic_link_confirmed(self, client: PassportClient) -> None:
        auth = AuthSession(
            track_id=_TEST_TRACK_ID,
            csrf_token=_TEST_CSRF,
            auth_methods=("magic_x_token",),
        )
        with aioresponses() as m:
            m.post(
                _MAGIC_STATUS_URL,
                status=200,
                payload={"status": "magic_link_confirmed"},
                headers=_JSON_CT,
            )
            _mock_token_exchange(m)
            _seed_session_cookies(client)
            creds = await client.poll_magic_link(auth, poll_interval=0.01, total_timeout=1.0)

        assert isinstance(creds, Credentials)

    async def test_poll_magic_link_timeout(self, client: PassportClient) -> None:
        auth = AuthSession(
            track_id=_TEST_TRACK_ID,
            csrf_token=_TEST_CSRF,
            auth_methods=("magic_x_token",),
        )
        with aioresponses() as m:
            # Keep returning pending — will timeout
            for _ in range(10):
                m.post(
                    _MAGIC_STATUS_URL,
                    status=200,
                    payload={"status": "pending"},
                    headers=_JSON_CT,
                )
            with pytest.raises(AuthFailedError, match="timed out"):
                await client.poll_magic_link(auth, poll_interval=0.01, total_timeout=0.05)


class TestCaptchaAuth:
    async def test_get_and_solve(self, client: PassportClient) -> None:
        auth = AuthSession(
            track_id=_TEST_TRACK_ID,
            csrf_token=_TEST_CSRF,
            auth_methods=("password",),
        )
        captcha_get_url = f"{PASSPORT_LEGACY_URL}/textcaptcha"
        captcha_check_url = f"{PASSPORT_LEGACY_URL}/checkHuman"

        with aioresponses() as m:
            m.post(
                captcha_get_url,
                status=200,
                payload={
                    "captcha_url": "https://captcha.yandex.net/image",
                    "key": "key-123",
                },
                headers=_JSON_CT,
            )
            challenge = await client.get_captcha(auth)

        assert isinstance(challenge, CaptchaChallenge)

        with aioresponses() as m:
            m.post(
                captcha_check_url,
                status=200,
                payload={"status": "ok"},
                headers=_JSON_CT,
            )
            result = await client.solve_captcha(auth, challenge, "answer")

        assert result is True


class TestLoginCookies:
    async def test_full_flow(self, client: PassportClient) -> None:
        with aioresponses() as m:
            m.post(
                _TOKEN_URL,
                status=200,
                payload={"access_token": _TEST_X_TOKEN},
                headers=_JSON_CT,
            )
            m.post(
                MUSIC_TOKEN_URL,
                status=200,
                payload={"access_token": _TEST_MUSIC_TOKEN},
                headers=_JSON_CT,
            )
            m.get(
                _ACCOUNT_URL,
                status=200,
                payload={"uid": 12345, "display_login": "testuser"},
                headers=_JSON_CT,
            )
            creds = await client.login_cookies("Session_id=abc; sessionid2=def")

        assert isinstance(creds, Credentials)
        assert creds.x_token.get_secret() == _TEST_X_TOKEN
        assert creds.music_token is not None
        assert creds.music_token.get_secret() == _TEST_MUSIC_TOKEN
        assert creds.uid == 12345


class TestPollMagicLinkValidation:
    async def test_invalid_poll_interval(self, client: PassportClient) -> None:
        auth = AuthSession(
            track_id=_TEST_TRACK_ID,
            csrf_token=_TEST_CSRF,
            auth_methods=("magic_x_token",),
        )
        with pytest.raises(ValueError, match="poll_interval"):
            await client.poll_magic_link(auth, poll_interval=-1)

    async def test_invalid_timeout(self, client: PassportClient) -> None:
        auth = AuthSession(
            track_id=_TEST_TRACK_ID,
            csrf_token=_TEST_CSRF,
            auth_methods=("magic_x_token",),
        )
        with pytest.raises(ValueError, match="total_timeout"):
            await client.poll_magic_link(auth, total_timeout=0)
