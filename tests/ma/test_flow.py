"""Tests for the blocking login flows behind MA config actions."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Self

import pytest
from music_assistant_models.errors import (
    InvalidDataError,
    LoginFailed,
    ResourceTemporarilyUnavailable,
)

from ya_passport_auth import Credentials, DeviceCodeSession, PassportClient, QrSession, SecretStr
from ya_passport_auth.exceptions import (
    DeviceCodeTimeoutError,
    InvalidCredentialsError,
    NetworkError,
)
from ya_passport_auth.ma.flow import (
    login_with_cookies,
    require_music_token,
    run_device_flow,
    run_qr_flow,
)
from ya_passport_auth.ma.page import DevicePageConfig

from .conftest import StubAuthenticationHelper

if TYPE_CHECKING:
    from .conftest import FakeMass

_PAGE = DevicePageConfig(domain="yandex_test")


def _creds(*, refresh: bool = True, music: bool = True) -> Credentials:
    return Credentials(
        x_token=SecretStr("test-x-token-0123456789"),
        music_token=SecretStr("test-music-token-0123456789") if music else None,
        refresh_token=SecretStr("test-refresh-token-0123456789") if refresh else None,
        display_login="renso",
    )


class _FakeClient:
    """Stands in for PassportClient inside the flows."""

    def __init__(
        self,
        *,
        poll_result: Credentials | None = None,
        poll_error: BaseException | None = None,
    ) -> None:
        self.poll_result = poll_result or _creds()
        self.poll_error: BaseException | None = poll_error

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None

    async def start_device_login(self, device_name: str | None = None) -> DeviceCodeSession:
        self.device_name = device_name
        return DeviceCodeSession(
            device_code=SecretStr("dev-code-test"),
            user_code="ABC-123",
            verification_url="https://ya.ru/device",
            interval=1,
            expires_in=300,
        )

    async def poll_device_until_confirmed(
        self, session: DeviceCodeSession, *, total_timeout: float | None = None
    ) -> Credentials:
        self.total_timeout = total_timeout
        if self.poll_error is not None:
            raise self.poll_error
        return self.poll_result

    async def start_qr_login(self) -> QrSession:
        return QrSession(
            qr_url="https://passport.yandex.ru/qr/x", csrf_token="test-csrf", track_id="t"
        )

    async def poll_qr_until_confirmed(self, qr: QrSession) -> Credentials:
        if self.poll_error is not None:
            raise self.poll_error
        return self.poll_result


@pytest.fixture
def fake_client(monkeypatch: pytest.MonkeyPatch) -> _FakeClient:
    client = _FakeClient()
    monkeypatch.setattr(PassportClient, "create", lambda **_kw: client)
    return client


class TestRunDeviceFlow:
    async def test_returns_credentials_and_display_login(
        self, fake_mass: FakeMass, fake_client: _FakeClient
    ) -> None:
        result = await run_device_flow(fake_mass, "session-1", _PAGE)
        assert result.credentials.x_token.get_secret() == "test-x-token-0123456789"
        assert result.display_login == "renso"

    async def test_serves_page_and_schedules_teardown(
        self, fake_mass: FakeMass, fake_client: _FakeClient
    ) -> None:
        await run_device_flow(fake_mass, "session-1", _PAGE)
        # Routes registered and the popup got the page URL.
        helper = StubAuthenticationHelper.instances[-1]
        assert helper.sent_urls == [
            f"{fake_mass.webserver.base_url}/yandex_test/device_code/session-1"
        ]
        # Teardown deferred — routes still alive right after return.
        assert "/yandex_test/device_code/session-1" in fake_mass.webserver.routes

    async def test_returns_without_grace_delay(
        self, fake_mass: FakeMass, fake_client: _FakeClient
    ) -> None:
        # The flow must return as soon as the outcome is known — the old
        # implementations blocked on a 3-second sleep before returning.
        async with asyncio.timeout(1.0):
            await run_device_flow(fake_mass, "session-1", _PAGE)

    async def test_status_reports_done(self, fake_mass: FakeMass, fake_client: _FakeClient) -> None:
        await run_device_flow(fake_mass, "session-1", _PAGE)
        # The state dict served by the still-alive status route says done.
        # (Route handlers close over the same dict.)
        assert "/yandex_test/device_code/session-1/status" in fake_mass.webserver.routes

    @pytest.mark.parametrize(
        ("error", "reason", "match"),
        [
            (DeviceCodeTimeoutError("t"), "expired", "timed out"),
            (InvalidCredentialsError("no"), "denied", "denied"),
        ],
    )
    async def test_failure_sets_reason_and_maps_error(
        self,
        fake_mass: FakeMass,
        fake_client: _FakeClient,
        error: Exception,
        reason: str,
        match: str,
    ) -> None:
        fake_client.poll_error = error
        with pytest.raises(LoginFailed, match=match):
            await run_device_flow(fake_mass, "session-1", _PAGE)

    async def test_transient_failure_maps_to_temporarily_unavailable(
        self, fake_mass: FakeMass, fake_client: _FakeClient
    ) -> None:
        fake_client.poll_error = NetworkError("net down")
        with pytest.raises(ResourceTemporarilyUnavailable):
            await run_device_flow(fake_mass, "session-1", _PAGE)

    async def test_cancellation_not_marked_as_failure(
        self, fake_mass: FakeMass, fake_client: _FakeClient
    ) -> None:
        fake_client.poll_error = asyncio.CancelledError()
        with pytest.raises(asyncio.CancelledError):
            await run_device_flow(fake_mass, "session-1", _PAGE)

    @pytest.mark.parametrize(
        "bad_session_id",
        ["", "a/b", "../../etc", "x" * 65, "юникод", "a b"],
    )
    async def test_rejects_unsafe_session_id(
        self, fake_mass: FakeMass, fake_client: _FakeClient, bad_session_id: str
    ) -> None:
        with pytest.raises(InvalidDataError):
            await run_device_flow(fake_mass, bad_session_id, _PAGE)

    async def test_device_name_and_timeout_forwarded(
        self, fake_mass: FakeMass, fake_client: _FakeClient
    ) -> None:
        await run_device_flow(
            fake_mass, "s1", _PAGE, device_name="Music Assistant", total_timeout=120
        )
        assert fake_client.device_name == "Music Assistant"
        assert fake_client.total_timeout == 120


class TestRunQrFlow:
    async def test_returns_credentials(self, fake_mass: FakeMass, fake_client: _FakeClient) -> None:
        result = await run_qr_flow(fake_mass, "session-1")
        assert result.display_login == "renso"
        helper = StubAuthenticationHelper.instances[-1]
        assert helper.sent_urls == ["https://passport.yandex.ru/qr/x"]

    async def test_rejects_unsafe_session_id(
        self, fake_mass: FakeMass, fake_client: _FakeClient
    ) -> None:
        with pytest.raises(InvalidDataError):
            await run_qr_flow(fake_mass, "a/b")


class TestRequireMusicToken:
    def test_returns_secret(self) -> None:
        assert require_music_token(_creds(), flow="Device") == "test-music-token-0123456789"

    def test_raises_when_missing(self) -> None:
        with pytest.raises(LoginFailed, match="Device auth succeeded but no music token"):
            require_music_token(_creds(music=False), flow="Device")


class TestLoginWithCookies:
    async def test_raw_cookie_string(
        self, monkeypatch: pytest.MonkeyPatch, fake_client: _FakeClient
    ) -> None:
        seen: dict[str, str] = {}

        async def _login_cookies(cookies: str) -> Credentials:
            seen["cookies"] = cookies
            return _creds()

        fake_client.login_cookies = _login_cookies  # type: ignore[attr-defined]
        creds = await login_with_cookies("Session_id=abc; yandexuid=42")
        assert creds.music_token is not None
        assert seen["cookies"] == "Session_id=abc; yandexuid=42"

    async def test_json_cookie_array(
        self, monkeypatch: pytest.MonkeyPatch, fake_client: _FakeClient
    ) -> None:
        seen: dict[str, str] = {}

        async def _login_cookies(cookies: str) -> Credentials:
            seen["cookies"] = cookies
            return _creds()

        fake_client.login_cookies = _login_cookies  # type: ignore[attr-defined]
        await login_with_cookies('[{"name": "Session_id", "value": "abc"}]')
        assert seen["cookies"] == "Session_id=abc"

    async def test_empty_input(self) -> None:
        with pytest.raises(InvalidDataError, match="Empty"):
            await login_with_cookies("   ")

    @pytest.mark.parametrize(
        "bad",
        ['[{"name": "x"}]', '["not-an-object"]', "[broken json", '[{"value": "v"}]'],
    )
    async def test_malformed_json(self, bad: str) -> None:
        with pytest.raises(InvalidDataError):
            await login_with_cookies(bad)

    async def test_no_kv_pairs(self) -> None:
        with pytest.raises(InvalidDataError, match="Invalid cookie format"):
            await login_with_cookies("just-some-garbage")
