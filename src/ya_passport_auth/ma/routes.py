"""Webserver route lifecycle for the device-code login page.

Combines the hardening accumulated across the MA yandex providers:

* per-request page render with an honest countdown (the remaining code
  lifetime is computed against a monotonic anchor, so late popup opens and
  reloads stay accurate) — from ``yandex_music``;
* status endpoint serving ``{"state", "reason"}`` so the page can show *why*
  a login failed — from ``yandex_music``;
* deferred, non-blocking teardown via ``mass.create_task`` with a takeover
  registry, so a rapid retry with the same session id takes the routes over
  instead of colliding — from ``yandex_music``;
* a 30-second grace window serving the terminal state (covers throttled
  background tabs and sleeping laptops) — from ``yandex_alice``;
* idempotent registration — from ``yandex_alice``.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import TYPE_CHECKING, Final

from aiohttp import web

from ._mass import as_mass
from .page import build_device_code_page

if TYPE_CHECKING:
    from collections.abc import Coroutine

    from ya_passport_auth import DeviceCodeSession

    from ._mass import MassLike, WebserverLike

_LOGGER = logging.getLogger(__name__)

__all__ = ["POST_AUTH_GRACE_SECONDS", "DeviceCodeRoutes"]

# Seconds to keep the routes alive after the flow finishes so the page can
# poll the terminal state and close itself, even from a throttled background
# tab. The wait runs in a background task — it never delays the config flow.
POST_AUTH_GRACE_SECONDS: Final = 30

# Pending deferred route teardowns keyed by page path, so a rapid retry with
# the same session id can take the routes over instead of colliding.
_pending_teardowns: dict[str, asyncio.Task[None] | asyncio.Future[None]] = {}


class DeviceCodeRoutes:
    """Owns the page + status routes of one device-code login session.

    Args:
        mass: The MusicAssistant instance (uses ``webserver`` and
            ``create_task``; structurally typed, see
            :class:`ya_passport_auth.ma._mass.MassLike`).
        domain: Provider domain — namespaces the route paths
            (``/<domain>/device_code/<session_id>``).
        session_id: Frontend-supplied config-flow session id (already
            validated by the caller, see :mod:`ya_passport_auth.ma.flow`).
    """

    def __init__(self, mass: object, domain: str, session_id: str) -> None:
        self._mass: MassLike = as_mass(mass)
        self.page_path = f"/{domain}/device_code/{session_id}"
        self.status_path = f"{self.page_path}/status"
        # Mutable login state shared with the flow; served as JSON.
        self.state: dict[str, str] = {"state": "pending"}

    @property
    def page_url(self) -> str:
        """Absolute URL of the login page (ingress-aware via MA's base_url)."""
        return f"{self._base_url()}{self.page_path}"

    @property
    def status_url(self) -> str:
        """Absolute URL of the status endpoint the page polls."""
        return f"{self._base_url()}{self.status_path}"

    def register(self, session: DeviceCodeSession, strings: dict[str, str]) -> None:
        """Register the page + status routes for *session*.

        Idempotent: any pending teardown for the same path is cancelled and
        existing registrations are dropped first, so a rapid retry with the
        same session id takes the routes over instead of colliding.

        Args:
            session: The device-code session issued by Yandex.
            strings: Resolved page strings (see
                :func:`ya_passport_auth.ma.strings.resolve_page_strings`).
        """
        webserver = self._mass.webserver
        issued_at = time.monotonic()
        status_url = self.status_url
        state = self.state

        async def _serve_page(_request: web.Request) -> web.Response:
            # Render per request so the countdown reflects the time the code
            # has actually left (late popup open, page reload).
            remaining = max(0, session.expires_in - int(time.monotonic() - issued_at))
            return web.Response(
                text=build_device_code_page(
                    user_code=session.user_code,
                    verification_url=session.verification_url,
                    status_url=status_url,
                    expires_in=remaining,
                    strings=strings,
                ),
                content_type="text/html",
                charset="utf-8",
                headers={
                    "Cache-Control": "no-store",
                    "Pragma": "no-cache",
                    "Expires": "0",
                },
            )

        async def _serve_status(_request: web.Request) -> web.Response:
            return web.json_response(dict(state), headers={"Cache-Control": "no-store"})

        self._cancel_pending_teardown()
        self._unregister_quietly(webserver, self.page_path)
        self._unregister_quietly(webserver, self.status_path)
        webserver.register_dynamic_route(self.page_path, _serve_page, "GET")
        webserver.register_dynamic_route(self.status_path, _serve_status, "GET")

    def schedule_teardown(self, grace_seconds: float = POST_AUTH_GRACE_SECONDS) -> None:
        """Unregister the routes after a grace period, without blocking.

        The page needs further polls to observe the terminal state (a
        throttled background tab may take many seconds to land its next
        request) — the routes stay alive for *grace_seconds* in the
        background instead of delaying the config flow's response.

        Args:
            grace_seconds: How long the terminal state stays reachable.
        """

        async def _teardown() -> None:
            await asyncio.sleep(grace_seconds)
            webserver = self._mass.webserver
            for path in (self.page_path, self.status_path):
                # The webserver may already be shutting down — one failed
                # unregister must not skip the remaining route.
                self._unregister_quietly(webserver, path)

        task = self._create_task(_teardown())
        _pending_teardowns[self.page_path] = task

        def _discard(done: asyncio.Task[None] | asyncio.Future[None]) -> None:
            if _pending_teardowns.get(self.page_path) is done:
                del _pending_teardowns[self.page_path]

        task.add_done_callback(_discard)

    def unregister_now(self) -> None:
        """Tear the routes down synchronously (module unload / hard cleanup)."""
        self._cancel_pending_teardown()
        webserver = self._mass.webserver
        for path in (self.page_path, self.status_path):
            self._unregister_quietly(webserver, path)

    def _base_url(self) -> str:
        try:
            base = self._mass.webserver.base_url
        except Exception:
            # An auth-critical URL degrading to a relative path must be
            # visible in logs — the popup may fail to open because of it.
            _LOGGER.warning(
                "Could not read MA base_url — device-code page URL will be relative",
                exc_info=True,
            )
            return ""
        return str(base).rstrip("/") if base else ""

    def _create_task(
        self, coro: Coroutine[object, object, None]
    ) -> asyncio.Task[None] | asyncio.Future[None]:
        try:
            # MA's task tracker — cancelled cleanly on shutdown, unhandled
            # exceptions are logged.
            return self._mass.create_task(coro)
        except (AttributeError, TypeError):
            return asyncio.get_running_loop().create_task(coro)

    def _cancel_pending_teardown(self) -> None:
        task = _pending_teardowns.pop(self.page_path, None)
        if task is not None:
            task.cancel()

    @staticmethod
    def _unregister_quietly(webserver: WebserverLike, path: str) -> None:
        try:
            webserver.unregister_dynamic_route(path, "GET")
        except Exception as err:
            _LOGGER.debug("Could not unregister route %s: %s", path, err)
