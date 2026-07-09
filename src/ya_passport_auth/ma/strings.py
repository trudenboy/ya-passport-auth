"""Resolution of device-code page strings through MA's translations.

Prefers the provider-owned ``strings.json`` catalog (``page.device_code.*``
keys, translated via Lokalise) and falls back per key to the built-in
English/Russian table when a translation is not yet available or the MA
build predates the translations controller.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .page import resolve_language

if TYPE_CHECKING:
    from .page import DevicePageConfig

_LOGGER = logging.getLogger(__name__)

__all__ = ["resolve_page_strings", "safe_locale"]


def safe_locale(mass: object) -> str | None:
    """Return the active MA locale string, or None when unavailable.

    Args:
        mass: The MusicAssistant instance (duck-typed; any object).
    """
    try:
        metadata = getattr(mass, "metadata", None)
        locale = getattr(metadata, "locale", None)
    except Exception:
        return None
    return locale if isinstance(locale, str) else None


async def resolve_page_strings(mass: object, page: DevicePageConfig) -> dict[str, str]:
    """Resolve the device-code page strings for the active MA locale.

    Args:
        mass: The MusicAssistant instance. Only ``metadata.locale`` and the
            optional ``translations`` controller are touched, defensively —
            the function never raises and always returns a full table.
        page: The provider's page configuration (domain = translation owner,
            plus title/context overrides applied to the fallback table).

    Returns:
        A complete string table for :func:`ya_passport_auth.ma.page.build_device_code_page`.
    """
    locale = safe_locale(mass)
    fallback = page.strings_for(resolve_language(locale))
    translations = getattr(mass, "translations", None)
    if translations is None:
        return fallback
    try:
        await translations.ensure_locale_loaded(locale)
    except Exception as err:
        _LOGGER.debug("Could not load locale catalog %s: %s", locale, err)
        return fallback
    for key in fallback:
        if key == "lang":
            continue
        try:
            value = translations.get_translation(
                f"page.device_code.{key}", locale=locale, owner=page.domain
            )
        except Exception as err:
            _LOGGER.debug("Translation lookup failed for %s: %s", key, err)
            return fallback
        if isinstance(value, str):
            fallback[key] = value
    return fallback
