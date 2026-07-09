"""Tests for the device-code page builder."""

from __future__ import annotations

import pytest

from ya_passport_auth.ma.page import (
    DEFAULT_PAGE_STRINGS,
    DevicePageConfig,
    build_device_code_page,
    resolve_language,
)


def _page(language: str = "en", config: DevicePageConfig | None = None) -> str:
    cfg = config or DevicePageConfig(domain="yandex_test")
    return build_device_code_page(
        user_code="ABC-123",
        verification_url="https://ya.ru/device",
        status_url="http://ma.local/x/device_code/s1/status",
        expires_in=300,
        strings=cfg.strings_for(language),
    )


class TestRendering:
    def test_renders_code_and_url(self) -> None:
        page = _page()
        assert "ABC-123" in page
        assert "https://ya.ru/device" in page

    def test_verification_url_shown_as_text_and_link(self) -> None:
        # Cross-device entry: the URL must be visible as text, not only a button.
        page = _page()
        assert '<div class="url">https://ya.ru/device</div>' in page
        assert 'href="https://ya.ru/device"' in page

    def test_copy_targets_code_block(self) -> None:
        # The code element itself is the copy control with execCommand fallback.
        page = _page()
        assert 'id="code" role="button"' in page
        assert "document.execCommand('copy')" in page

    def test_countdown_and_terminal_states(self) -> None:
        page = _page()
        assert 'id="countdown"' in page
        assert "let remaining = 300" in page
        assert "expired_title" in page
        assert "r.status === 404 || r.status === 410" in page

    def test_failure_reasons_handled(self) -> None:
        page = _page()
        assert "data.reason === 'expired'" in page
        assert "data.reason === 'denied'" in page

    def test_dark_theme(self) -> None:
        assert "prefers-color-scheme: dark" in _page()

    def test_html_escaping(self) -> None:
        page = build_device_code_page(
            user_code="<b>x</b>",
            verification_url="https://ya.ru/device?a=1&b=2",
            status_url="http://ma.local/s",
            expires_in=10,
            strings=DevicePageConfig(domain="d").strings_for("en"),
        )
        assert "<b>x</b>" not in page
        assert "&lt;b&gt;x&lt;/b&gt;" in page
        assert "a=1&amp;b=2" in page

    def test_script_breakout_escaped(self) -> None:
        page = build_device_code_page(
            user_code="X",
            verification_url="https://ya.ru/device",
            status_url="http://ma.local/</script><script>alert(1)",
            expires_in=10,
            strings=DevicePageConfig(domain="d").strings_for("en"),
        )
        assert "</script><script>alert(1)" not in page


class TestLocalization:
    def test_russian(self) -> None:
        page = _page("ru")
        assert 'lang="ru"' in page
        assert "Скопируйте код" in page

    def test_unknown_language_falls_back_to_english(self) -> None:
        page = _page("de")
        assert 'lang="en"' in page

    def test_resolve_language(self) -> None:
        assert resolve_language("ru_RU") == "ru"
        assert resolve_language("RU") == "ru"
        assert resolve_language("en_US") == "en"
        assert resolve_language(None) == "en"

    def test_all_languages_share_key_set(self) -> None:
        keys = {frozenset(table) for table in DEFAULT_PAGE_STRINGS.values()}
        assert len(keys) == 1


class TestConfigOverrides:
    def test_title_override(self) -> None:
        cfg = DevicePageConfig(
            domain="yandex_station",
            title={"en": "Login to Yandex Station", "ru": "Вход в Яндекс Станцию"},
        )
        assert "<title>Login to Yandex Station</title>" in _page("en", cfg)
        assert "Вход в Яндекс Станцию" in _page("ru", cfg)

    def test_context_paragraph(self) -> None:
        cfg = DevicePageConfig(
            domain="yandex_alice",
            context_text={"en": "MA will register the skill on your behalf."},
        )
        page = _page("en", cfg)
        assert '<p class="context">MA will register the skill on your behalf.</p>' in page

    def test_no_context_paragraph_by_default(self) -> None:
        assert '<p class="context">' not in _page()

    @pytest.mark.parametrize("language", ["en", "ru"])
    def test_strings_for_returns_copy(self, language: str) -> None:
        cfg = DevicePageConfig(domain="d")
        table = cfg.strings_for(language)
        table["title"] = "mutated"
        assert DEFAULT_PAGE_STRINGS[language]["title"] != "mutated"
