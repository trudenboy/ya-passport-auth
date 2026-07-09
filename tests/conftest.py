"""Shared test configuration.

Compatibility shim: aiohttp 3.14 added a required keyword-only
``stream_writer`` argument to ``ClientResponse.__init__``, and released
aioresponses (<=0.7.9) does not pass it when constructing mocked responses.
Until the upstream fixes ship (pnuckowski/aioresponses#288, #292), point
aioresponses at a subclass that defaults the argument. The value is only
consulted for its ``output_size`` attribute, so a lightweight mock suffices.
Remove this module once aioresponses supports aiohttp 3.14.
"""

import asyncio
import inspect
from unittest.mock import Mock

import aioresponses.core
from aiohttp import ClientResponse, StreamReader
from aiohttp.client_proto import ResponseHandler
from yarl import URL

if "stream_writer" in inspect.signature(ClientResponse.__init__).parameters:

    class _CompatClientResponse(ClientResponse):
        def __init__(self, method: str, url: URL, **kwargs: object) -> None:
            kwargs.setdefault("stream_writer", Mock(output_size=0))
            super().__init__(method, url, **kwargs)  # type: ignore[arg-type]

    aioresponses.core.ClientResponse = _CompatClientResponse  # type: ignore[attr-defined]

    def _compat_stream_reader_factory(
        loop: asyncio.AbstractEventLoop | None = None,
    ) -> StreamReader:
        protocol = ResponseHandler(loop=loop)  # type: ignore[arg-type]
        # Bodies larger than the StreamReader limit trigger BaseProtocol's
        # flow-control hooks, which assert a parser is attached.
        parser = Mock()
        parser.feed_data.return_value = ([], False, b"")
        protocol._parser = parser
        return StreamReader(protocol, limit=2**16, loop=loop)

    aioresponses.core.stream_reader_factory = _compat_stream_reader_factory  # type: ignore[attr-defined]
