"""Narrow structural views of the MusicAssistant runtime.

The ``ma`` layer never imports the ``music_assistant`` server package at
module level — providers hand over the live ``mass`` object and these
protocols describe the handful of attributes actually touched. Tests pass
lightweight fakes; the real MusicAssistant instance satisfies the protocols
structurally.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Coroutine
from typing import TYPE_CHECKING, Protocol, cast, runtime_checkable

if TYPE_CHECKING:
    import asyncio

    from aiohttp import web

__all__ = ["MassLike", "TranslationsLike", "WebserverLike", "as_mass"]

Handler = Callable[["web.Request"], Awaitable["web.Response"]]


@runtime_checkable
class WebserverLike(Protocol):
    """The slice of MA's webserver controller used by the ma layer."""

    @property
    def base_url(self) -> str:
        """Public base URL (ingress-aware in HA add-on mode)."""
        ...

    def register_dynamic_route(self, path: str, handler: Handler, method: str) -> object:
        """Register a dynamic route."""
        ...

    def unregister_dynamic_route(self, path: str, method: str) -> object:
        """Unregister a dynamic route."""
        ...


class TranslationsLike(Protocol):
    """The slice of MA's translations controller used by the ma layer."""

    async def ensure_locale_loaded(self, locale: str | None) -> None:
        """Warm up the locale catalog."""
        ...

    def get_translation(
        self, key: str, locale: str | None = None, owner: str | None = None
    ) -> str | None:
        """Resolve a translation key."""
        ...


class MassLike(Protocol):
    """The slice of the MusicAssistant instance used by the ma layer."""

    @property
    def webserver(self) -> WebserverLike:
        """The webserver controller."""
        ...

    def create_task(
        self, coro: Coroutine[object, object, None]
    ) -> asyncio.Task[None] | asyncio.Future[None]:
        """Schedule a tracked background task."""
        ...


def as_mass(mass: object) -> MassLike:
    """View an arbitrary ``mass`` object through the :class:`MassLike` protocol.

    Args:
        mass: The MusicAssistant instance (or a test fake).
    """
    return cast("MassLike", mass)
