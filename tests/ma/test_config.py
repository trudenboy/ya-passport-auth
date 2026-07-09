"""Tests for the standard auth config-entry block."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from music_assistant_models.errors import InvalidDataError

from ya_passport_auth import Credentials, SecretStr
from ya_passport_auth.ma import config as config_mod
from ya_passport_auth.ma.cascade import KeySpec
from ya_passport_auth.ma.config import (
    ACTION_AUTH_COOKIES,
    ACTION_AUTH_DEVICE,
    ACTION_AUTH_QR,
    ACTION_CLEAR_AUTH,
    AuthConfigSpec,
    build_auth_config_entries,
    handle_auth_action,
    is_authenticated,
)
from ya_passport_auth.ma.flow import FlowResult
from ya_passport_auth.ma.page import DevicePageConfig

if TYPE_CHECKING:
    from music_assistant_models.config_entries import ConfigEntry, ConfigValueType

_PAGE = DevicePageConfig(domain="yandex_test")
_SPEC = AuthConfigSpec(flows=frozenset({"device", "qr", "cookies"}))


def _creds() -> Credentials:
    return Credentials(
        x_token=SecretStr("test-x-0123456789"),
        music_token=SecretStr("test-music-0123456789"),
        refresh_token=SecretStr("test-refresh-0123456789"),
        display_login="renso",
    )


def _by_key(entries: tuple[ConfigEntry, ...]) -> dict[str, ConfigEntry]:
    return {entry.key: entry for entry in entries}


class TestBuildEntries:
    def test_full_flow_set(self) -> None:
        entries = _by_key(build_auth_config_entries(_SPEC, {}, status_label="s"))
        assert set(entries) == {
            "label_text",
            ACTION_AUTH_DEVICE,
            ACTION_AUTH_QR,
            "remember_session",
            "cookies",
            ACTION_AUTH_COOKIES,
            ACTION_CLEAR_AUTH,
            "x_token",
            "music_token",
            "refresh_token",
        }

    def test_no_hardcoded_texts(self) -> None:
        # Labels/descriptions come from strings.json — code passes none
        # (except the dynamic status label).
        entries = build_auth_config_entries(_SPEC, {}, status_label="status here")
        for entry in entries:
            if entry.key == "label_text":
                assert entry.label == "status here"
                continue
            assert entry.label is None
            assert entry.description is None
            assert entry.action_label is None

    def test_qr_only_spec(self) -> None:
        spec = AuthConfigSpec(flows=frozenset({"qr"}), store_refresh_token=False)
        entries = _by_key(build_auth_config_entries(spec, {}, status_label="s"))
        assert ACTION_AUTH_DEVICE not in entries
        assert ACTION_AUTH_COOKIES not in entries
        assert "refresh_token" not in entries

    def test_visibility_flips_after_auth(self) -> None:
        anon = _by_key(build_auth_config_entries(_SPEC, {}, status_label="s"))
        authed_values: dict[str, ConfigValueType] = {"music_token": "test-music-0123456789"}
        authed = _by_key(build_auth_config_entries(_SPEC, authed_values, status_label="s"))
        assert anon[ACTION_AUTH_DEVICE].hidden is False
        assert authed[ACTION_AUTH_DEVICE].hidden is True
        assert anon[ACTION_CLEAR_AUTH].hidden is True
        assert authed[ACTION_CLEAR_AUTH].hidden is False

    def test_remember_session_visibility_flag(self) -> None:
        values: dict[str, ConfigValueType] = {"music_token": "test-music-0123456789"}
        keep = _by_key(build_auth_config_entries(_SPEC, values, status_label="s"))
        assert keep["remember_session"].hidden is False
        hide_spec = AuthConfigSpec(flows=frozenset({"qr"}), remember_visible_after_auth=False)
        hidden = _by_key(build_auth_config_entries(hide_spec, values, status_label="s"))
        assert hidden["remember_session"].hidden is True

    def test_token_storage_carries_values(self) -> None:
        values: dict[str, ConfigValueType] = {
            "x_token": "test-x-0123456789",
            "music_token": "test-music-0123456789",
        }
        entries = _by_key(build_auth_config_entries(_SPEC, values, status_label="s"))
        assert entries["x_token"].value == "test-x-0123456789"
        assert entries["x_token"].hidden is True

    def test_custom_key_names(self) -> None:
        spec = AuthConfigSpec(keys=KeySpec(music_token="token"), flows=frozenset({"qr"}))
        entries = _by_key(build_auth_config_entries(spec, {}, status_label="s"))
        assert "token" in entries
        assert "music_token" not in entries


class TestIsAuthenticated:
    def test_music_token(self) -> None:
        assert is_authenticated(_SPEC, {"music_token": "t"}) is True

    def test_x_token(self) -> None:
        assert is_authenticated(_SPEC, {"x_token": "t"}) is True

    def test_empty(self) -> None:
        assert is_authenticated(_SPEC, {"music_token": None}) is False


class TestHandleAuthAction:
    @pytest.fixture
    def flows(self, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
        calls: dict[str, object] = {}

        async def fake_device(
            mass: object, session_id: str, page: object, **kwargs: object
        ) -> FlowResult:
            calls["device"] = session_id
            return FlowResult(credentials=_creds(), display_login="renso")

        async def fake_qr(mass: object, session_id: str) -> FlowResult:
            calls["qr"] = session_id
            return FlowResult(credentials=_creds(), display_login="renso")

        async def fake_cookies(cookies_input: str) -> Credentials:
            calls["cookies"] = cookies_input
            return _creds()

        monkeypatch.setattr(config_mod, "run_device_flow", fake_device)
        monkeypatch.setattr(config_mod, "run_qr_flow", fake_qr)
        monkeypatch.setattr(config_mod, "login_with_cookies", fake_cookies)
        return calls

    async def test_device_action(self, flows: dict[str, object]) -> None:
        values: dict[str, ConfigValueType] = {"session_id": "s1"}
        await handle_auth_action(object(), _SPEC, _PAGE, ACTION_AUTH_DEVICE, values)
        assert values["x_token"] == "test-x-0123456789"
        assert values["music_token"] == "test-music-0123456789"
        assert values["refresh_token"] == "test-refresh-0123456789"

    async def test_device_action_requires_session_id(self, flows: dict[str, object]) -> None:
        with pytest.raises(InvalidDataError):
            await handle_auth_action(object(), _SPEC, _PAGE, ACTION_AUTH_DEVICE, {})

    async def test_qr_action_clears_refresh_token(self, flows: dict[str, object]) -> None:
        values: dict[str, ConfigValueType] = {"session_id": "s1"}
        await handle_auth_action(object(), _SPEC, _PAGE, ACTION_AUTH_QR, values)
        assert values["refresh_token"] is None

    async def test_cookies_action_drops_raw_cookies(self, flows: dict[str, object]) -> None:
        values: dict[str, ConfigValueType] = {"cookies": "Session_id=abc"}
        await handle_auth_action(object(), _SPEC, _PAGE, ACTION_AUTH_COOKIES, values)
        assert values["cookies"] is None
        assert values["x_token"] == "test-x-0123456789"

    async def test_cookies_action_requires_input(self, flows: dict[str, object]) -> None:
        with pytest.raises(InvalidDataError):
            await handle_auth_action(object(), _SPEC, _PAGE, ACTION_AUTH_COOKIES, {})

    async def test_clear_action(self, flows: dict[str, object]) -> None:
        values: dict[str, ConfigValueType] = {
            "x_token": "test-x-0123456789",
            "music_token": "test-music-0123456789",
            "refresh_token": "test-refresh-0123456789",
        }
        await handle_auth_action(object(), _SPEC, _PAGE, ACTION_CLEAR_AUTH, values)
        assert values["x_token"] is None
        assert values["music_token"] is None
        assert values["refresh_token"] is None

    async def test_remember_off_drops_long_lived_tokens(self, flows: dict[str, object]) -> None:
        values: dict[str, ConfigValueType] = {
            "x_token": "test-x-0123456789",
            "music_token": "test-music-0123456789",
            "refresh_token": "test-refresh-0123456789",
            "remember_session": False,
        }
        await handle_auth_action(object(), _SPEC, _PAGE, None, values)
        assert values["x_token"] is None
        assert values["refresh_token"] is None
        assert values["music_token"] == "test-music-0123456789"

    async def test_custom_keys(self, flows: dict[str, object]) -> None:
        spec = AuthConfigSpec(keys=KeySpec(music_token="token"))
        values: dict[str, ConfigValueType] = {"session_id": "s1"}
        await handle_auth_action(object(), spec, _PAGE, ACTION_AUTH_QR, values)
        assert values["token"] == "test-music-0123456789"
