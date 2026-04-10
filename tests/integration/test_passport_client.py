"""Integration tests for ``PassportClient`` facade.

End-to-end with mocked transport — verifies the full wiring from
facade method → flow → SafeHttpClient → aioresponses.
"""

from __future__ import annotations

from pathlib import Path

import aiohttp
import pytest
from aioresponses import aioresponses
from yarl import URL

from ya_passport_auth.client import PassportClient
from ya_passport_auth.config import ClientConfig
from ya_passport_auth.credentials import Credentials, SecretStr
from ya_passport_auth.exceptions import QRTimeoutError
from ya_passport_auth.flows.qr import QrSession

FIXTURES = Path(__file__).parent.parent / "fixtures"

_PASSPORT = "https://passport.yandex.ru"
_PROXY = "https://mobileproxy.passport.yandex.net"
_OAUTH = "https://oauth.mobile.yandex.net"
_QUASAR = "https://iot.quasar.yandex.ru"
_GLAGOL = "https://quasar.yandex.net"
_JSON_CT = {"Content-Type": "application/json"}
_HTML_CT = {"Content-Type": "text/html; charset=utf-8"}

_TEST_X_TOKEN = "test-xtoken-facade-0123456789"
_TEST_MUSIC_TOKEN = "test-musictoken-facade-abcdef"
_TEST_TRACK_ID = "test-track-id-facade"
_TEST_CSRF = "test-csrf-facade-01234567890"


def _fast_config() -> ClientConfig:
    return ClientConfig(
        min_request_interval_seconds=0.001,
        qr_poll_interval_seconds=0.01,
        qr_poll_total_timeout_seconds=0.05,
    )


class TestPassportClientCreate:
    async def test_create_context_manager(self) -> None:
        async with PassportClient.create(config=_fast_config()) as client:
            assert client is not None

    async def test_manual_lifecycle(self) -> None:
        client = PassportClient(config=_fast_config())
        await client.close()


class TestQrLoginIntegration:
    async def test_start_qr_login(self) -> None:
        html = (FIXTURES / "csrf_input_attr.html").read_text()
        async with PassportClient.create(config=_fast_config()) as client:
            with aioresponses() as m:
                m.get(
                    f"{_PASSPORT}/am?app_platform=android",
                    status=200,
                    body=html,
                    headers=_HTML_CT,
                )
                m.post(
                    f"{_PASSPORT}/registration-validations/auth/password/submit",
                    status=200,
                    payload={
                        "status": "ok",
                        "track_id": _TEST_TRACK_ID,
                        "csrf_token": _TEST_CSRF,
                    },
                    headers=_JSON_CT,
                )
                qr = await client.start_qr_login()
            assert qr.track_id == _TEST_TRACK_ID
            assert "track_id=" in qr.qr_url

    async def test_poll_timeout(self) -> None:
        async with PassportClient.create(config=_fast_config()) as client:
            qr = QrSession(
                track_id=_TEST_TRACK_ID,
                csrf_token=_TEST_CSRF,
                qr_url="http://x",
            )
            with aioresponses() as m:
                # Return "pending" many times — enough to exhaust the timeout.
                for _ in range(20):
                    m.post(
                        f"{_PASSPORT}/auth/new/magic/status/",
                        status=200,
                        payload={"status": "pending"},
                        headers=_JSON_CT,
                    )
                with pytest.raises(QRTimeoutError):
                    await client.poll_qr_until_confirmed(qr)

    async def test_poll_success(self) -> None:
        async with PassportClient.create(config=_fast_config()) as client:
            client._session.cookie_jar.update_cookies(
                {"Session_id": "s1", "sessionid2": "s2"},
                response_url=URL(_PASSPORT),
            )
            qr = QrSession(
                track_id=_TEST_TRACK_ID,
                csrf_token=_TEST_CSRF,
                qr_url="http://x",
            )
            with aioresponses() as m:
                # First poll: pending. Second: ok.
                m.post(
                    f"{_PASSPORT}/auth/new/magic/status/",
                    status=200,
                    payload={"status": "pending"},
                    headers=_JSON_CT,
                )
                m.post(
                    f"{_PASSPORT}/auth/new/magic/status/",
                    status=200,
                    payload={"status": "ok"},
                    headers=_JSON_CT,
                )
                # x_token exchange
                m.post(
                    f"{_PROXY}/1/bundle/oauth/token_by_sessionid",
                    status=200,
                    payload={"access_token": _TEST_X_TOKEN},
                    headers=_JSON_CT,
                )
                # music_token exchange
                m.post(
                    f"{_OAUTH}/1/token",
                    status=200,
                    payload={"access_token": _TEST_MUSIC_TOKEN},
                    headers=_JSON_CT,
                )
                # account info
                m.get(
                    f"{_PROXY}/1/bundle/account/short_info/",
                    status=200,
                    payload={"uid": 99, "display_login": "poll.user"},
                    headers=_JSON_CT,
                )
                creds = await client.poll_qr_until_confirmed(qr)
            assert isinstance(creds, Credentials)
            assert creds.uid == 99


class TestCompleteQrLogin:
    async def test_full_flow(self) -> None:
        async with PassportClient.create(config=_fast_config()) as client:
            # Seed session cookies (simulating a confirmed QR scan).
            client._session.cookie_jar.update_cookies(
                {"Session_id": "s1", "sessionid2": "s2"},
                response_url=URL(_PASSPORT),
            )
            qr = QrSession(
                track_id=_TEST_TRACK_ID,
                csrf_token=_TEST_CSRF,
                qr_url="http://x",
            )
            with aioresponses() as m:
                # x_token exchange
                m.post(
                    f"{_PROXY}/1/bundle/oauth/token_by_sessionid",
                    status=200,
                    payload={"access_token": _TEST_X_TOKEN},
                    headers=_JSON_CT,
                )
                # music_token exchange
                m.post(
                    f"{_OAUTH}/1/token",
                    status=200,
                    payload={"access_token": _TEST_MUSIC_TOKEN},
                    headers=_JSON_CT,
                )
                # account info
                m.get(
                    f"{_PROXY}/1/bundle/account/short_info/",
                    status=200,
                    payload={"uid": 42, "display_login": "qr.user"},
                    headers=_JSON_CT,
                )
                creds = await client.complete_qr_login(qr)
            assert isinstance(creds, Credentials)
            assert creds.x_token.get_secret() == _TEST_X_TOKEN
            assert creds.music_token is not None
            assert creds.music_token.get_secret() == _TEST_MUSIC_TOKEN
            assert creds.uid == 42
            assert creds.display_login == "qr.user"

    async def test_account_info_failure_still_returns_creds(self) -> None:
        async with PassportClient.create(config=_fast_config()) as client:
            client._session.cookie_jar.update_cookies(
                {"Session_id": "s1"},
                response_url=URL(_PASSPORT),
            )
            qr = QrSession(
                track_id=_TEST_TRACK_ID,
                csrf_token=_TEST_CSRF,
                qr_url="http://x",
            )
            with aioresponses() as m:
                m.post(
                    f"{_PROXY}/1/bundle/oauth/token_by_sessionid",
                    status=200,
                    payload={"access_token": _TEST_X_TOKEN},
                    headers=_JSON_CT,
                )
                m.post(
                    f"{_OAUTH}/1/token",
                    status=200,
                    payload={"access_token": _TEST_MUSIC_TOKEN},
                    headers=_JSON_CT,
                )
                # account info fails
                m.get(
                    f"{_PROXY}/1/bundle/account/short_info/",
                    status=200,
                    payload={"status_code": 401},
                    headers=_JSON_CT,
                )
                creds = await client.complete_qr_login(qr)
            assert creds.x_token.get_secret() == _TEST_X_TOKEN
            assert creds.uid is None
            assert creds.display_login is None


class TestClientLifecycle:
    async def test_aenter_aexit(self) -> None:
        async with PassportClient(config=_fast_config()) as client:
            assert client is not None

    async def test_external_session(self) -> None:
        async with aiohttp.ClientSession() as session:
            client = PassportClient(session=session, config=_fast_config())
            # Client doesn't own the session, so close should not close it.
            await client.close()
            assert not session.closed


class TestTokenOps:
    async def test_refresh_music_token(self) -> None:
        async with PassportClient.create(config=_fast_config()) as client:
            with aioresponses() as m:
                m.post(
                    f"{_OAUTH}/1/token",
                    status=200,
                    payload={"access_token": _TEST_MUSIC_TOKEN},
                    headers=_JSON_CT,
                )
                token = await client.refresh_music_token(SecretStr(_TEST_X_TOKEN))
            assert token.get_secret() == _TEST_MUSIC_TOKEN

    async def test_validate_x_token_valid(self) -> None:
        async with PassportClient.create(config=_fast_config()) as client:
            with aioresponses() as m:
                m.get(
                    f"{_PROXY}/1/bundle/account/short_info/",
                    status=200,
                    payload={"uid": 123, "display_login": "user"},
                    headers=_JSON_CT,
                )
                assert await client.validate_x_token(SecretStr(_TEST_X_TOKEN)) is True

    async def test_validate_x_token_invalid(self) -> None:
        async with PassportClient.create(config=_fast_config()) as client:
            with aioresponses() as m:
                m.get(
                    f"{_PROXY}/1/bundle/account/short_info/",
                    status=200,
                    payload={"status_code": 401},
                    headers=_JSON_CT,
                )
                assert await client.validate_x_token(SecretStr(_TEST_X_TOKEN)) is False

    async def test_fetch_account_info(self) -> None:
        async with PassportClient.create(config=_fast_config()) as client:
            with aioresponses() as m:
                m.get(
                    f"{_PROXY}/1/bundle/account/short_info/",
                    status=200,
                    payload={
                        "uid": 777,
                        "display_login": "me",
                        "display_name": "Me",
                    },
                    headers=_JSON_CT,
                )
                info = await client.fetch_account_info(SecretStr(_TEST_X_TOKEN))
            assert info.uid == 777
            assert info.display_login == "me"

    async def test_get_quasar_csrf_token(self) -> None:
        async with PassportClient.create(config=_fast_config()) as client:
            with aioresponses() as m:
                m.get(
                    f"{_QUASAR}/m/v3/user/devices",
                    status=200,
                    payload={"status": "ok"},
                    headers={**_JSON_CT, "x-csrf-token": "csrf-quasar-val"},
                )
                token = await client.get_quasar_csrf_token()
            assert token.get_secret() == "csrf-quasar-val"

    async def test_get_glagol_device_token(self) -> None:
        async with PassportClient.create(config=_fast_config()) as client:
            with aioresponses() as m:
                m.get(
                    f"{_GLAGOL}/glagol/token?device_id=d1&platform=yandexstation",
                    status=200,
                    payload={"status": "ok", "token": "glagol-tok"},
                    headers=_JSON_CT,
                )
                token = await client.get_glagol_device_token(
                    SecretStr(_TEST_MUSIC_TOKEN),
                    device_id="d1",
                    platform="yandexstation",
                )
            assert token.get_secret() == "glagol-tok"

    async def test_refresh_passport_cookies(self) -> None:
        async with PassportClient.create(config=_fast_config()) as client:
            with aioresponses() as m:
                m.post(
                    f"{_PROXY}/1/bundle/auth/x_token/",
                    status=200,
                    payload={
                        "status": "ok",
                        "passport_host": _PASSPORT,
                        "track_id": "t123",
                    },
                    headers=_JSON_CT,
                )
                m.get(
                    f"{_PASSPORT}/auth/session/",
                    status=200,
                    body="<html>ok</html>",
                    headers=_HTML_CT,
                )
                await client.refresh_passport_cookies(SecretStr(_TEST_X_TOKEN))


class TestNoTokenLeakInRepr:
    async def test_credentials_repr_clean(self) -> None:
        creds = Credentials(
            x_token=SecretStr(_TEST_X_TOKEN),
            music_token=SecretStr(_TEST_MUSIC_TOKEN),
        )
        rendered = repr(creds)
        assert _TEST_X_TOKEN not in rendered
        assert _TEST_MUSIC_TOKEN not in rendered
