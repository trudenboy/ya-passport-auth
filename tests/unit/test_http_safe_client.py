"""Tests for ``SafeHttpClient``.

``SafeHttpClient`` wraps an :class:`aiohttp.ClientSession` with the
following invariants:

* **Host allow-list** — every response URL must come from
  ``ClientConfig.allowed_hosts`` or :class:`UnexpectedHostError` is
  raised. Redirects are disabled so an attacker cannot bounce the
  request through a foreign host.
* **Size caps** — JSON responses larger than 1 MiB and HTML larger
  than 2 MiB raise :class:`NetworkError`. This blocks the trivial
  DoS where a compromised response tries to exhaust client memory.
* **Rate limiting** — every request calls the injected
  :class:`AsyncMinDelayLimiter` before touching the network.
* **HTTP 429** → :class:`RateLimitedError`, no retry.
* **Network errors** → :class:`NetworkError` with ``endpoint`` set
  (sanitised by the exception constructor).
* **Content type enforcement** — ``get_json`` requires a
  JSON-ish content type; an HTML body served on a JSON endpoint
  raises :class:`NetworkError`.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest
from aioresponses import aioresponses
from yarl import URL

from ya_passport_auth.config import ClientConfig
from ya_passport_auth.exceptions import (
    NetworkError,
    RateLimitedError,
    UnexpectedHostError,
)
from ya_passport_auth.http import SafeHttpClient
from ya_passport_auth.rate_limit import AsyncMinDelayLimiter

_OK_URL = "https://passport.yandex.ru/test"
_JSON_HEADERS = {"Content-Type": "application/json"}
_HTML_HEADERS = {"Content-Type": "text/html; charset=utf-8"}


@pytest.fixture
def config() -> ClientConfig:
    return ClientConfig(min_request_interval_seconds=0.001)


@pytest.fixture
async def session() -> AsyncGenerator[aiohttp.ClientSession, None]:
    async with aiohttp.ClientSession() as s:
        yield s


@pytest.fixture
def limiter() -> AsyncMinDelayLimiter:
    return AsyncMinDelayLimiter(min_interval_seconds=0.001)


@pytest.fixture
def client(
    session: aiohttp.ClientSession,
    config: ClientConfig,
    limiter: AsyncMinDelayLimiter,
) -> SafeHttpClient:
    return SafeHttpClient(session=session, config=config, limiter=limiter)


class TestAllowedHost:
    async def test_allowed_host_passes(self, client: SafeHttpClient) -> None:
        with aioresponses() as mocked:
            mocked.get(_OK_URL, status=200, payload={"ok": True}, headers=_JSON_HEADERS)
            result = await client.get_json(_OK_URL)
        assert result == {"ok": True}

    async def test_disallowed_host_raises(self, client: SafeHttpClient) -> None:
        with aioresponses() as mocked, pytest.raises(UnexpectedHostError):
            mocked.get(
                "https://evil.example.com/x",
                status=200,
                payload={"ok": True},
                headers=_JSON_HEADERS,
            )
            await client.get_json("https://evil.example.com/x")

    async def test_redirects_disabled(self, client: SafeHttpClient) -> None:
        """Even a 302 to an allowed host is rejected — the library
        never follows redirects."""
        with aioresponses() as mocked:
            mocked.get(
                _OK_URL,
                status=302,
                headers={"Location": "https://passport.yandex.ru/other"},
            )
            with pytest.raises(NetworkError):
                await client.get_json(_OK_URL)

    async def test_response_url_host_mismatch_raises(
        self,
        session: aiohttp.ClientSession,
        config: ClientConfig,
        limiter: AsyncMinDelayLimiter,
    ) -> None:
        """Defence-in-depth: even if the request URL is allowed, the
        response's final URL must ALSO be on the allow-list. Redirects
        are disabled so this cannot happen via aiohttp in practice —
        the second ``_check_host`` exists to protect against future
        regressions. We exercise it by stubbing ``session.request``."""
        fake_response = MagicMock(spec=aiohttp.ClientResponse)
        fake_response.status = 200
        fake_response.url = URL("https://evil.example.com/x")
        fake_response.release = MagicMock()

        stub = AsyncMock(return_value=fake_response)
        session.request = stub  # type: ignore[method-assign]

        client = SafeHttpClient(session=session, config=config, limiter=limiter)
        with pytest.raises(UnexpectedHostError):
            await client.get_json(_OK_URL)
        # The response must be released on this failure path — otherwise
        # a connection leaks back into the pool half-read.
        fake_response.release.assert_called_once()


class TestContentType:
    async def test_non_json_response_raises(self, client: SafeHttpClient) -> None:
        with aioresponses() as mocked:
            mocked.get(_OK_URL, status=200, body="<html>", headers=_HTML_HEADERS)
            with pytest.raises(NetworkError, match="content-type"):
                await client.get_json(_OK_URL)

    async def test_get_html_accepts_html(self, client: SafeHttpClient) -> None:
        with aioresponses() as mocked:
            mocked.get(
                _OK_URL,
                status=200,
                body="<html><body>ok</body></html>",
                headers=_HTML_HEADERS,
            )
            text = await client.get_text(_OK_URL)
        assert "ok" in text


class TestRateLimited:
    async def test_http_429_raises_no_retry(self, client: SafeHttpClient) -> None:
        with aioresponses() as mocked:
            mocked.get(
                _OK_URL,
                status=429,
                payload={"error": "too many"},
                headers=_JSON_HEADERS,
            )
            with pytest.raises(RateLimitedError) as excinfo:
                await client.get_json(_OK_URL)

        assert excinfo.value.status_code == 429
        assert excinfo.value.endpoint is not None
        assert "passport.yandex.ru" in excinfo.value.endpoint


class TestNetworkError:
    async def test_connection_failure_wrapped(self, client: SafeHttpClient) -> None:
        with aioresponses() as mocked:
            mocked.get(_OK_URL, exception=aiohttp.ClientConnectionError("boom"))
            with pytest.raises(NetworkError) as excinfo:
                await client.get_json(_OK_URL)
        assert excinfo.value.endpoint is not None


class TestSizeCaps:
    async def test_json_body_over_cap_raises(self, client: SafeHttpClient) -> None:
        # 1 MiB + 1 byte of filler — exceeds the 1 MiB cap
        huge = '{"x":"' + ("a" * (1024 * 1024 + 1)) + '"}'
        with aioresponses() as mocked:
            mocked.get(_OK_URL, status=200, body=huge, headers=_JSON_HEADERS)
            with pytest.raises(NetworkError, match="size"):
                await client.get_json(_OK_URL)

    async def test_html_body_over_cap_raises(self, client: SafeHttpClient) -> None:
        huge = "<html>" + ("a" * (2 * 1024 * 1024 + 1)) + "</html>"
        with aioresponses() as mocked:
            mocked.get(_OK_URL, status=200, body=huge, headers=_HTML_HEADERS)
            with pytest.raises(NetworkError, match="size"):
                await client.get_text(_OK_URL)

    async def test_json_body_at_cap_passes(self, client: SafeHttpClient) -> None:
        # Exactly at the cap: 1 MiB of payload.
        # Build a valid JSON ≤1 MiB.
        body = '{"x":"' + ("a" * (1024 * 1024 - 10)) + '"}'
        assert len(body) <= 1024 * 1024
        with aioresponses() as mocked:
            mocked.get(_OK_URL, status=200, body=body, headers=_JSON_HEADERS)
            result = await client.get_json(_OK_URL)
        assert "x" in result


class TestRateLimiting:
    async def test_enforces_rate_limit(
        self,
        session: aiohttp.ClientSession,
        config: ClientConfig,
    ) -> None:
        """The limiter passed in must be invoked on every request."""
        calls: list[None] = []

        class CountingLimiter(AsyncMinDelayLimiter):
            async def acquire(self) -> None:
                calls.append(None)
                await super().acquire()

        limiter = CountingLimiter(min_interval_seconds=0.001)
        client = SafeHttpClient(session=session, config=config, limiter=limiter)

        with aioresponses() as mocked:
            mocked.get(_OK_URL, status=200, payload={"ok": True}, headers=_JSON_HEADERS)
            mocked.get(_OK_URL, status=200, payload={"ok": True}, headers=_JSON_HEADERS)
            await client.get_json(_OK_URL)
            await client.get_json(_OK_URL)

        assert len(calls) == 2


class TestGetJsonWithHeaders:
    async def test_returns_body_and_headers(self, client: SafeHttpClient) -> None:
        with aioresponses() as mocked:
            mocked.get(
                _OK_URL,
                status=200,
                payload={"ok": True},
                headers={**_JSON_HEADERS, "x-custom": "val"},
            )
            body, headers = await client.get_json_with_headers(_OK_URL)
        assert body == {"ok": True}
        assert headers.get("x-custom") == "val"

    async def test_non_json_content_type_raises(self, client: SafeHttpClient) -> None:
        with aioresponses() as mocked:
            mocked.get(_OK_URL, status=200, body="<html>", headers=_HTML_HEADERS)
            with pytest.raises(NetworkError, match="content-type"):
                await client.get_json_with_headers(_OK_URL)

    async def test_invalid_json_body_raises(self, client: SafeHttpClient) -> None:
        with aioresponses() as mocked:
            mocked.get(_OK_URL, status=200, body="not json", headers=_JSON_HEADERS)
            with pytest.raises(NetworkError, match="invalid JSON"):
                await client.get_json_with_headers(_OK_URL)

    async def test_non_object_json_raises(self, client: SafeHttpClient) -> None:
        with aioresponses() as mocked:
            mocked.get(_OK_URL, status=200, body="[1]", headers=_JSON_HEADERS)
            with pytest.raises(NetworkError, match="expected JSON object"):
                await client.get_json_with_headers(_OK_URL)


class TestInvalidJson:
    async def test_invalid_json_body_raises(self, client: SafeHttpClient) -> None:
        with aioresponses() as mocked:
            mocked.get(_OK_URL, status=200, body="not json{{{", headers=_JSON_HEADERS)
            with pytest.raises(NetworkError, match="invalid JSON"):
                await client.get_json(_OK_URL)

    async def test_json_array_instead_of_object_raises(self, client: SafeHttpClient) -> None:
        with aioresponses() as mocked:
            mocked.get(_OK_URL, status=200, body="[1,2,3]", headers=_JSON_HEADERS)
            with pytest.raises(NetworkError, match="expected JSON object"):
                await client.get_json(_OK_URL)


class TestPost:
    async def test_post_json_allowed_host(self, client: SafeHttpClient) -> None:
        with aioresponses() as mocked:
            mocked.post(
                _OK_URL,
                status=200,
                payload={"status": "ok"},
                headers=_JSON_HEADERS,
            )
            result = await client.post_json(_OK_URL, data={"k": "v"})
        assert result == {"status": "ok"}

    async def test_post_disallowed_host(self, client: SafeHttpClient) -> None:
        with aioresponses() as mocked, pytest.raises(UnexpectedHostError):
            mocked.post(
                "https://evil.example.com/x",
                status=200,
                payload={},
                headers=_JSON_HEADERS,
            )
            await client.post_json("https://evil.example.com/x", data={})
