"""Security-hardened async HTTP client used by every Yandex flow.

``SafeHttpClient`` is a thin wrapper around :class:`aiohttp.ClientSession`
that enforces the library's network invariants on every request:

* Host allow-list — the response URL's host must be in
  :attr:`ClientConfig.allowed_hosts` (T4). Redirects are disabled so
  a compromised endpoint cannot bounce the request to a foreign host.
* Response size caps — JSON bodies are capped at 1 MiB and HTML
  bodies at 2 MiB (T5).
* Rate limiting — every request goes through an injected
  :class:`AsyncMinDelayLimiter` (T7).
* HTTP 429 → :class:`RateLimitedError`, no retry. Network errors
  (connection refused, TLS failure) → :class:`NetworkError`.
* Structured errors — every exception carries the request endpoint
  (sanitised by the exception constructor so query strings do not
  leak).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Final

import aiohttp
from yarl import URL

from ya_passport_auth.exceptions import (
    NetworkError,
    RateLimitedError,
    UnexpectedHostError,
)
from ya_passport_auth.logging import get_logger

if TYPE_CHECKING:
    from ya_passport_auth.config import ClientConfig
    from ya_passport_auth.rate_limit import AsyncMinDelayLimiter

__all__ = ["HTML_MAX_BYTES", "JSON_MAX_BYTES", "SafeHttpClient"]

_log = get_logger("http")

JSON_MAX_BYTES: Final = 1 * 1024 * 1024
HTML_MAX_BYTES: Final = 2 * 1024 * 1024

_JSON_CONTENT_TYPES: Final = frozenset(
    {"application/json", "application/x-javascript", "text/json"},
)


def _content_type(response: aiohttp.ClientResponse) -> str:
    raw = response.headers.get("Content-Type", "")
    return raw.split(";", 1)[0].strip().lower()


class SafeHttpClient:
    """Hardened aiohttp wrapper enforcing the library's network policy."""

    __slots__ = ("_config", "_limiter", "_session")

    def __init__(
        self,
        *,
        session: aiohttp.ClientSession,
        config: ClientConfig,
        limiter: AsyncMinDelayLimiter,
    ) -> None:
        self._session = session
        self._config = config
        self._limiter = limiter

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    async def get_json(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> dict[str, object]:
        """GET a JSON endpoint and return the parsed body."""
        return await self._request_json("GET", url, headers=headers, data=None)

    async def post_json(
        self,
        url: str,
        *,
        data: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, object]:
        """POST form data and return the parsed JSON body."""
        return await self._request_json("POST", url, headers=headers, data=data)

    async def get_json_with_headers(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> tuple[dict[str, object], dict[str, str]]:
        """GET a JSON endpoint and return ``(parsed_body, response_headers)``."""
        response = await self._execute("GET", url, headers=headers, data=None)
        try:
            content_type = _content_type(response)
            if content_type not in _JSON_CONTENT_TYPES:
                raise NetworkError(
                    f"unexpected content-type {content_type!r}",
                    status_code=response.status,
                    endpoint=url,
                )
            body = await self._read_capped(response, JSON_MAX_BYTES, url)
            resp_headers = dict(response.headers)
        finally:
            response.release()

        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:
            raise NetworkError(
                f"invalid JSON body: {exc}",
                status_code=response.status,
                endpoint=url,
            ) from exc
        if not isinstance(parsed, dict):
            raise NetworkError(
                f"expected JSON object, got {type(parsed).__name__}",
                status_code=response.status,
                endpoint=url,
            )
        return parsed, resp_headers

    async def get_text(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
    ) -> str:
        """GET an HTML/text endpoint and return the body as a string."""
        response = await self._execute("GET", url, headers=headers, data=None)
        try:
            body = await self._read_capped(response, HTML_MAX_BYTES, url)
        finally:
            response.release()
        return body.decode("utf-8", errors="replace")

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    async def _request_json(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None,
        data: dict[str, object] | None,
    ) -> dict[str, object]:
        response = await self._execute(method, url, headers=headers, data=data)
        try:
            content_type = _content_type(response)
            if content_type not in _JSON_CONTENT_TYPES:
                raise NetworkError(
                    f"unexpected content-type {content_type!r}",
                    status_code=response.status,
                    endpoint=url,
                )
            body = await self._read_capped(response, JSON_MAX_BYTES, url)
        finally:
            response.release()

        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:
            raise NetworkError(
                f"invalid JSON body: {exc}",
                status_code=response.status,
                endpoint=url,
            ) from exc
        if not isinstance(parsed, dict):
            raise NetworkError(
                f"expected JSON object, got {type(parsed).__name__}",
                status_code=response.status,
                endpoint=url,
            )
        return parsed

    async def _execute(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None,
        data: dict[str, object] | None,
    ) -> aiohttp.ClientResponse:
        self._check_host(url)
        await self._limiter.acquire()

        merged_headers = {
            "User-Agent": self._config.user_agent,
            **(headers or {}),
        }
        timeout = aiohttp.ClientTimeout(
            total=self._config.total_timeout_seconds,
            connect=self._config.connect_timeout_seconds,
        )

        try:
            response = await self._session.request(
                method,
                url,
                headers=merged_headers,
                data=data,
                timeout=timeout,
                allow_redirects=False,
            )
        except aiohttp.ClientError as exc:
            raise NetworkError(
                f"{method} request failed: {exc}",
                endpoint=url,
            ) from exc

        # Re-check the host of the actual response URL — aiohttp with
        # ``allow_redirects=False`` will still surface a 3xx; we refuse it.
        if 300 <= response.status < 400:
            response.release()
            raise NetworkError(
                f"unexpected redirect ({response.status})",
                status_code=response.status,
                endpoint=url,
            )
        self._check_host(str(response.url))

        if response.status == 429:
            response.release()
            raise RateLimitedError(
                "rate limited by upstream",
                status_code=429,
                endpoint=url,
            )
        return response

    def _check_host(self, url: str) -> None:
        host = URL(url).host
        if host is None or host not in self._config.allowed_hosts:
            raise UnexpectedHostError(
                f"host {host!r} is not in the allow-list",
                endpoint=url,
            )

    async def _read_capped(
        self,
        response: aiohttp.ClientResponse,
        cap: int,
        url: str,
    ) -> bytes:
        # Read incrementally so oversized responses are rejected before
        # the entire body is buffered in memory.
        chunks: list[bytes] = []
        total = 0
        async for chunk in response.content.iter_chunked(65536):
            total += len(chunk)
            if total > cap:
                response.close()
                raise NetworkError(
                    f"response size exceeds cap {cap}",
                    status_code=response.status,
                    endpoint=url,
                )
            chunks.append(chunk)
        return b"".join(chunks)
