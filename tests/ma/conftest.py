"""Shared fixtures for the ma-layer tests.

The MA *server* package is never installed in this repo — a minimal stub of
``music_assistant.helpers.auth.AuthenticationHelper`` is injected so the
flow modules' lazy imports resolve. The stub records the URL sent to the
frontend and otherwise behaves as an async no-op context manager.
"""

from __future__ import annotations

import asyncio
import sys
import types
from dataclasses import dataclass, field
from typing import ClassVar, Self

import pytest


class StubAuthenticationHelper:
    """Records ``send_url`` calls; async context manager no-op."""

    instances: ClassVar[list[StubAuthenticationHelper]] = []

    def __init__(self, mass: object, session_id: str) -> None:
        self.mass = mass
        self.session_id = session_id
        self.sent_urls: list[str] = []
        StubAuthenticationHelper.instances.append(self)

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None

    def send_url(self, url: str) -> None:
        self.sent_urls.append(url)


@pytest.fixture(autouse=True)
def _stub_music_assistant(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provide ``music_assistant.helpers.auth`` for the lazy flow imports."""
    StubAuthenticationHelper.instances.clear()
    if "music_assistant.helpers.auth" in sys.modules:
        monkeypatch.setattr(
            sys.modules["music_assistant.helpers.auth"],
            "AuthenticationHelper",
            StubAuthenticationHelper,
            raising=False,
        )
        return
    pkg = types.ModuleType("music_assistant")
    helpers = types.ModuleType("music_assistant.helpers")
    auth = types.ModuleType("music_assistant.helpers.auth")
    auth.AuthenticationHelper = StubAuthenticationHelper  # type: ignore[attr-defined]
    pkg.helpers = helpers  # type: ignore[attr-defined]
    helpers.auth = auth  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "music_assistant", pkg)
    monkeypatch.setitem(sys.modules, "music_assistant.helpers", helpers)
    monkeypatch.setitem(sys.modules, "music_assistant.helpers.auth", auth)


@dataclass
class FakeWebserver:
    """In-memory register/unregister ledger standing in for MA's webserver."""

    base_url: str = "http://ma.local:8095"
    routes: dict[str, object] = field(default_factory=dict)
    unregister_calls: list[str] = field(default_factory=list)
    raise_on_unregister: bool = False

    def register_dynamic_route(self, path: str, handler: object, method: str = "GET") -> None:
        if path in self.routes:
            msg = f"route already registered: {path}"
            raise RuntimeError(msg)
        self.routes[path] = handler

    def unregister_dynamic_route(self, path: str, method: str = "GET") -> None:
        self.unregister_calls.append(path)
        if self.raise_on_unregister:
            msg = "webserver shutting down"
            raise RuntimeError(msg)
        self.routes.pop(path, None)


class FakeMass:
    """Minimal MassLike test double."""

    def __init__(self) -> None:
        self.webserver = FakeWebserver()
        self.created: list[object] = []

    def create_task(self, coro: object) -> object:
        task: asyncio.Task[None] = asyncio.get_running_loop().create_task(coro)  # type: ignore[arg-type]
        self.created.append(task)
        return task


@pytest.fixture
def fake_mass() -> FakeMass:
    """A fresh FakeMass per test."""
    return FakeMass()
