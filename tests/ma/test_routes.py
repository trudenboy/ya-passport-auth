"""Tests for the device-code route lifecycle."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, cast

import pytest

from ya_passport_auth import DeviceCodeSession, SecretStr
from ya_passport_auth.ma.page import DevicePageConfig
from ya_passport_auth.ma.routes import DeviceCodeRoutes

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from aiohttp import web

    from .conftest import FakeMass


def _session(expires_in: int = 300) -> DeviceCodeSession:
    return DeviceCodeSession(
        device_code=SecretStr("dev-code-test"),
        user_code="ABC-123",
        verification_url="https://ya.ru/device",
        interval=2,
        expires_in=expires_in,
    )


def _strings() -> dict[str, str]:
    return DevicePageConfig(domain="yandex_test").strings_for("en")


async def _call(handler: object) -> str:
    handler_fn = cast("Callable[[object], Awaitable[web.Response]]", handler)
    response = await handler_fn(None)
    return str(response.text)


class TestRegistration:
    async def test_registers_page_and_status(self, fake_mass: FakeMass) -> None:
        routes = DeviceCodeRoutes(fake_mass, "yandex_test", "s1")
        routes.register(_session(), _strings())
        assert "/yandex_test/device_code/s1" in fake_mass.webserver.routes
        assert "/yandex_test/device_code/s1/status" in fake_mass.webserver.routes

    async def test_urls_are_ingress_aware(self, fake_mass: FakeMass) -> None:
        fake_mass.webserver.base_url = "http://ma.local:8095/addon/"
        routes = DeviceCodeRoutes(fake_mass, "yandex_test", "s1")
        assert routes.page_url == "http://ma.local:8095/addon/yandex_test/device_code/s1"
        assert routes.status_url.endswith("/s1/status")

    async def test_reregistration_takes_over(self, fake_mass: FakeMass) -> None:
        # A rapid retry with the same session id must not collide.
        first = DeviceCodeRoutes(fake_mass, "yandex_test", "s1")
        first.register(_session(), _strings())
        second = DeviceCodeRoutes(fake_mass, "yandex_test", "s1")
        second.register(_session(), _strings())
        assert fake_mass.webserver.routes  # re-registered, no RuntimeError

    async def test_page_served_with_no_store(self, fake_mass: FakeMass) -> None:
        routes = DeviceCodeRoutes(fake_mass, "yandex_test", "s1")
        routes.register(_session(), _strings())
        handler = cast(
            "Callable[[object], Awaitable[web.Response]]",
            fake_mass.webserver.routes["/yandex_test/device_code/s1"],
        )
        response = await handler(None)
        assert response.headers["Cache-Control"] == "no-store"
        assert "ABC-123" in str(response.text)


class TestHonestCountdown:
    async def test_countdown_reflects_elapsed_time(
        self, fake_mass: FakeMass, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        now = {"t": 1000.0}
        monkeypatch.setattr("ya_passport_auth.ma.routes.time.monotonic", lambda: now["t"])
        routes = DeviceCodeRoutes(fake_mass, "yandex_test", "s1")
        routes.register(_session(expires_in=300), _strings())
        page_handler = fake_mass.webserver.routes["/yandex_test/device_code/s1"]

        assert "let remaining = 300" in await _call(page_handler)
        now["t"] = 1120.0  # 2 minutes later (late popup open / reload)
        assert "let remaining = 180" in await _call(page_handler)
        now["t"] = 2000.0  # long past expiry — clamps at zero
        assert "let remaining = 0" in await _call(page_handler)


class TestStatusEndpoint:
    async def test_status_serves_state_and_reason(self, fake_mass: FakeMass) -> None:
        routes = DeviceCodeRoutes(fake_mass, "yandex_test", "s1")
        routes.register(_session(), _strings())
        routes.state.update({"state": "failed", "reason": "denied"})
        handler = cast(
            "Callable[[object], Awaitable[web.Response]]",
            fake_mass.webserver.routes["/yandex_test/device_code/s1/status"],
        )
        response = await handler(None)
        body = str(response.text)
        assert '"state": "failed"' in body
        assert '"reason": "denied"' in body


class TestTeardown:
    async def test_teardown_is_deferred_and_non_blocking(self, fake_mass: FakeMass) -> None:
        routes = DeviceCodeRoutes(fake_mass, "yandex_test", "s1")
        routes.register(_session(), _strings())
        routes.schedule_teardown(grace_seconds=0.01)
        # Returns immediately; routes still up until the grace elapses.
        assert "/yandex_test/device_code/s1" in fake_mass.webserver.routes
        await asyncio.sleep(0.05)
        assert "/yandex_test/device_code/s1" not in fake_mass.webserver.routes
        assert "/yandex_test/device_code/s1/status" not in fake_mass.webserver.routes

    async def test_reregistration_cancels_pending_teardown(self, fake_mass: FakeMass) -> None:
        routes = DeviceCodeRoutes(fake_mass, "yandex_test", "s1")
        routes.register(_session(), _strings())
        routes.schedule_teardown(grace_seconds=0.05)
        retry = DeviceCodeRoutes(fake_mass, "yandex_test", "s1")
        retry.register(_session(), _strings())
        await asyncio.sleep(0.1)
        # The retry took the routes over; the old teardown must not fire.
        assert "/yandex_test/device_code/s1" in fake_mass.webserver.routes

    async def test_teardown_attempts_every_path_despite_errors(self, fake_mass: FakeMass) -> None:
        routes = DeviceCodeRoutes(fake_mass, "yandex_test", "s1")
        routes.register(_session(), _strings())
        fake_mass.webserver.raise_on_unregister = True
        routes.schedule_teardown(grace_seconds=0.01)
        await asyncio.sleep(0.05)
        attempted = [
            path
            for path in fake_mass.webserver.unregister_calls
            if path.startswith("/yandex_test/device_code/s1")
        ]
        assert "/yandex_test/device_code/s1" in attempted
        assert "/yandex_test/device_code/s1/status" in attempted

    async def test_unregister_now(self, fake_mass: FakeMass) -> None:
        routes = DeviceCodeRoutes(fake_mass, "yandex_test", "s1")
        routes.register(_session(), _strings())
        routes.unregister_now()
        assert not fake_mass.webserver.routes
