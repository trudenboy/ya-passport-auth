"""Integration test: no tokens appear in logs across the full QR flow.

Threat model T1 — verifies that the library's RedactingFilter prevents
any token-like string from surfacing in captured log output during a
complete QR login end-to-end.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from aioresponses import aioresponses
from yarl import URL

from ya_passport_auth.client import PassportClient
from ya_passport_auth.config import ClientConfig
from ya_passport_auth.constants import DEVICE_CODE_URL, OAUTH_TOKEN_URL
from ya_passport_auth.credentials import Credentials, SecretStr
from ya_passport_auth.flows.qr import QrSession
from ya_passport_auth.models import DeviceCodeSession, OAuthTokens

_PASSPORT = "https://passport.yandex.ru"
_PROXY = "https://mobileproxy.passport.yandex.net"
_OAUTH = "https://oauth.mobile.yandex.net"
_JSON_CT = {"Content-Type": "application/json"}
_HTML_CT = {"Content-Type": "text/html; charset=utf-8"}
FIXTURES = Path(__file__).parent.parent / "fixtures"

_SECRET_X = "test-xtoken-f1e2d3c4b5a69788"
_SECRET_MUSIC = "test-musictoken-99887766aabbccdd"
_SECRET_DEVICE = "test-devicecode-a1b2c3d4e5f67890"
_SECRET_ACCESS = "test-access-token-ff00ff00aabbccdd"
_SECRET_REFRESH = "test-refresh-token-1122334455667788"


def _fast_config() -> ClientConfig:
    return ClientConfig(min_request_interval_seconds=0.001)


class TestNoTokenLeakInLogs:
    async def test_full_qr_flow_logs_clean(self, caplog: pytest.LogCaptureFixture) -> None:
        caplog.set_level(logging.DEBUG, logger="ya_passport_auth")
        html = (FIXTURES / "csrf_input_attr.html").read_text()

        async with PassportClient.create(config=_fast_config()) as client:
            client._session.cookie_jar.update_cookies(
                {"Session_id": "s1", "sessionid2": "s2"},
                response_url=URL(_PASSPORT),
            )
            with aioresponses() as m:
                # QR start
                m.get(
                    f"{_PASSPORT}/am?app_platform=android",
                    status=200,
                    body=html,
                    headers=_HTML_CT,
                )
                m.post(
                    f"{_PASSPORT}/pwl-yandex/api/passport/auth/multistep_start",
                    status=200,
                    payload={"track_id": "track-123"},
                    headers=_JSON_CT,
                )
                m.post(
                    f"{_PASSPORT}/pwl-yandex/api/passport/auth/password/submit",
                    status=200,
                    payload={
                        "track_id": "track-123",
                        "csrf_token": "csrf-tok",
                    },
                    headers=_JSON_CT,
                )
                # x_token exchange
                m.post(
                    f"{_PROXY}/1/bundle/oauth/token_by_sessionid",
                    status=200,
                    payload={"access_token": _SECRET_X},
                    headers=_JSON_CT,
                )
                # music_token exchange
                m.post(
                    f"{_OAUTH}/1/token",
                    status=200,
                    payload={"access_token": _SECRET_MUSIC},
                    headers=_JSON_CT,
                )
                # account info
                m.get(
                    f"{_PROXY}/1/bundle/account/short_info/?avatar_size=islands-300",
                    status=200,
                    payload={"uid": 1, "display_login": "u"},
                    headers=_JSON_CT,
                )

                qr = await client.start_qr_login()
                qr_with_cookies = QrSession(
                    track_id=qr.track_id,
                    csrf_token=qr.csrf_token,
                    qr_url=qr.qr_url,
                )
                await client.complete_qr_login(qr_with_cookies)

        # Now verify no token-like strings leaked into any log record.
        all_log_text = " ".join(r.getMessage() for r in caplog.records)
        assert _SECRET_X not in all_log_text, "x_token leaked into logs"
        assert _SECRET_MUSIC not in all_log_text, "music_token leaked into logs"

    async def test_full_device_flow_logs_clean(self, caplog: pytest.LogCaptureFixture) -> None:
        caplog.set_level(logging.DEBUG, logger="ya_passport_auth")

        async with PassportClient.create(config=_fast_config()) as client:
            with aioresponses() as m:
                m.post(
                    DEVICE_CODE_URL,
                    status=200,
                    payload={
                        "device_code": _SECRET_DEVICE,
                        "user_code": "leakcode",
                        "verification_url": "https://ya.ru/device",
                        "expires_in": 30,
                        "interval": 1,
                    },
                    headers=_JSON_CT,
                )
                m.post(
                    OAUTH_TOKEN_URL,
                    status=200,
                    payload={
                        "access_token": _SECRET_ACCESS,
                        "refresh_token": _SECRET_REFRESH,
                        "expires_in": 31_536_000,
                    },
                    headers=_JSON_CT,
                )
                m.post(
                    f"{_OAUTH}/1/token",
                    status=200,
                    payload={"access_token": _SECRET_MUSIC},
                    headers=_JSON_CT,
                )
                m.get(
                    f"{_PROXY}/1/bundle/account/short_info/?avatar_size=islands-300",
                    status=200,
                    payload={"uid": 1, "display_login": "u"},
                    headers=_JSON_CT,
                )

                def on_code(_: DeviceCodeSession) -> None:
                    pass

                await client.login_device_code(on_code=on_code, poll_interval=0.01)

        all_log_text = " ".join(r.getMessage() for r in caplog.records)
        assert _SECRET_DEVICE not in all_log_text
        assert _SECRET_ACCESS not in all_log_text
        assert _SECRET_REFRESH not in all_log_text
        assert _SECRET_MUSIC not in all_log_text
        assert "leakcode" not in all_log_text, "user_code leaked into logs"


class TestNoTokenLeakInRepr:
    def test_device_code_session_repr_clean(self) -> None:
        session = DeviceCodeSession(
            device_code=SecretStr(_SECRET_DEVICE),
            user_code="usercode1",
            verification_url="https://ya.ru/device",
            expires_in=300,
            interval=5,
        )
        rendered = repr(session)
        assert _SECRET_DEVICE not in rendered

    def test_oauth_tokens_repr_clean(self) -> None:
        tokens = OAuthTokens(
            access_token=SecretStr(_SECRET_ACCESS),
            refresh_token=SecretStr(_SECRET_REFRESH),
            expires_in=100,
        )
        rendered = repr(tokens)
        assert _SECRET_ACCESS not in rendered
        assert _SECRET_REFRESH not in rendered

    def test_credentials_with_refresh_token_repr_clean(self) -> None:
        creds = Credentials(
            x_token=SecretStr(_SECRET_ACCESS),
            music_token=SecretStr(_SECRET_MUSIC),
            refresh_token=SecretStr(_SECRET_REFRESH),
        )
        rendered = repr(creds)
        assert _SECRET_ACCESS not in rendered
        assert _SECRET_MUSIC not in rendered
        assert _SECRET_REFRESH not in rendered
