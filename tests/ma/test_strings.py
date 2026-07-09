"""Tests for MA-translations resolution of the page strings."""

from __future__ import annotations

from ya_passport_auth.ma.page import DevicePageConfig
from ya_passport_auth.ma.strings import resolve_page_strings, safe_locale

_PAGE = DevicePageConfig(domain="yandex_test")


class _Metadata:
    def __init__(self, locale: object) -> None:
        self.locale = locale


class _Translations:
    def __init__(
        self,
        catalog: dict[str, str] | None = None,
        *,
        fail_load: bool = False,
        fail_lookup: bool = False,
    ) -> None:
        self.catalog = catalog or {}
        self.fail_load = fail_load
        self.fail_lookup = fail_lookup
        self.loaded: list[str | None] = []

    async def ensure_locale_loaded(self, locale: str | None) -> None:
        if self.fail_load:
            msg = "catalog unavailable"
            raise RuntimeError(msg)
        self.loaded.append(locale)

    def get_translation(
        self, key: str, locale: str | None = None, owner: str | None = None
    ) -> str | None:
        if self.fail_lookup:
            msg = "lookup exploded"
            raise RuntimeError(msg)
        return self.catalog.get(f"{owner}::{key}")


class _Mass:
    def __init__(self, locale: object = "en_US", translations: object = None) -> None:
        self.metadata = _Metadata(locale)
        if translations is not None:
            self.translations = translations


class TestSafeLocale:
    def test_returns_locale(self) -> None:
        assert safe_locale(_Mass("ru_RU")) == "ru_RU"

    def test_non_string_locale(self) -> None:
        assert safe_locale(_Mass(42)) is None

    def test_missing_metadata(self) -> None:
        assert safe_locale(object()) is None


class TestResolvePageStrings:
    async def test_missing_controller_falls_back(self) -> None:
        strings = await resolve_page_strings(_Mass("ru_RU"), _PAGE)
        assert strings["lang"] == "ru"
        assert strings["step_copy"] == "Скопируйте код"

    async def test_translated_value_wins(self) -> None:
        translations = _Translations(
            {"yandex_test::page.device_code.title": "Übersetzter Titel"},
        )
        strings = await resolve_page_strings(_Mass("de_DE", translations), _PAGE)
        assert strings["title"] == "Übersetzter Titel"
        # Untranslated keys keep the built-in English fallback.
        assert strings["step_copy"] == "Copy the code"
        assert translations.loaded == ["de_DE"]

    async def test_lang_key_never_overridden(self) -> None:
        translations = _Translations({"yandex_test::page.device_code.lang": "xx"})
        strings = await resolve_page_strings(_Mass("en_US", translations), _PAGE)
        assert strings["lang"] == "en"

    async def test_catalog_load_failure_falls_back(self) -> None:
        translations = _Translations(fail_load=True)
        strings = await resolve_page_strings(_Mass("ru_RU", translations), _PAGE)
        assert strings["lang"] == "ru"

    async def test_lookup_failure_falls_back(self) -> None:
        translations = _Translations(fail_lookup=True)
        strings = await resolve_page_strings(_Mass("en_US", translations), _PAGE)
        assert strings["title"] == "Login to Yandex"

    async def test_owner_is_page_domain(self) -> None:
        translations = _Translations(
            {"yandex_station::page.device_code.title": "Station title"},
        )
        page = DevicePageConfig(domain="yandex_station")
        strings = await resolve_page_strings(_Mass("en_US", translations), page)
        assert strings["title"] == "Station title"
