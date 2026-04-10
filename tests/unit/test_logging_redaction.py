"""Tests for ``RedactingFilter`` and ``get_logger``.

Threat model mapping:
- T1 (token leak via logs): every logged record must be scrubbed of
  obvious token shapes before a handler sees it.
- T12 (log injection via attacker-controlled strings): CR/LF in the
  formatted message must be replaced with a visible marker so a single
  log entry cannot forge a second line.
"""

from __future__ import annotations

import logging

import pytest

from ya_passport_auth.credentials import SecretStr
from ya_passport_auth.logging import RedactingFilter, get_logger


@pytest.fixture
def captured(caplog: pytest.LogCaptureFixture) -> pytest.LogCaptureFixture:
    # Capture the whole library namespace so any get_logger("…") child
    # is visible under the same fixture.
    caplog.set_level(logging.DEBUG, logger="ya_passport_auth")
    return caplog


def _log(logger: logging.Logger, msg: str, *args: object) -> None:
    logger.info(msg, *args)


class TestRedactingFilter:
    def test_redacts_oauth_bearer(self, captured: pytest.LogCaptureFixture) -> None:
        logger = get_logger("test")
        _log(logger, "sending header: %s", "OAuth abcdef0123456789abcdef0123456789")
        rendered = captured.records[-1].getMessage()
        assert "abcdef0123456789abcdef0123456789" not in rendered
        assert "OAuth ***" in rendered

    def test_redacts_32plus_hex_runs(self, captured: pytest.LogCaptureFixture) -> None:
        logger = get_logger("test")
        hex_token = "a" * 40
        _log(logger, "got token: %s", hex_token)
        rendered = captured.records[-1].getMessage()
        assert hex_token not in rendered
        assert "***" in rendered

    def test_preserves_short_hex(self, captured: pytest.LogCaptureFixture) -> None:
        """Short hex (e.g. a ``uid`` or status code) must not be scrubbed."""
        logger = get_logger("test")
        _log(logger, "uid=%s status=%s", "abc123", 200)
        rendered = captured.records[-1].getMessage()
        assert "abc123" in rendered
        assert "200" in rendered

    def test_redacts_secretstr_repr(self, captured: pytest.LogCaptureFixture) -> None:
        logger = get_logger("test")
        s = SecretStr("super-secret-value")
        _log(logger, "secret=%s", s)
        rendered = captured.records[-1].getMessage()
        assert "super-secret-value" not in rendered
        assert "***" in rendered

    def test_scrubs_crlf_injection(self, captured: pytest.LogCaptureFixture) -> None:
        logger = get_logger("test")
        _log(logger, "user input: %s", "hello\r\nFAKE LINE")
        rendered = captured.records[-1].getMessage()
        assert "\r" not in rendered
        assert "\n" not in rendered
        assert "FAKE LINE" in rendered  # kept, but on the same line


class TestGetLogger:
    def test_returns_namespaced_logger(self) -> None:
        logger = get_logger("qr")
        assert logger.name == "ya_passport_auth.qr"

    def test_filter_attached_once(self) -> None:
        logger = get_logger("idempotent")
        first = [f for f in logger.filters if isinstance(f, RedactingFilter)]
        # Calling again must not stack filters.
        get_logger("idempotent")
        second = [f for f in logger.filters if isinstance(f, RedactingFilter)]
        assert len(first) == 1
        assert len(second) == 1

    def test_child_logger_inherits_redaction(self, captured: pytest.LogCaptureFixture) -> None:
        logger = get_logger("child")
        _log(logger, "value=%s", "OAuth deadbeefdeadbeefdeadbeefdeadbeef")
        rendered = captured.records[-1].getMessage()
        assert "deadbeefdeadbeefdeadbeefdeadbeef" not in rendered


class TestFilterStandalone:
    def test_filter_handles_malformed_args(self) -> None:
        """If ``%s`` substitution blows up, the filter still scrubs
        the raw ``record.msg`` instead of crashing the caller."""
        flt = RedactingFilter()
        record = logging.LogRecord(
            name="ya_passport_auth.direct",
            level=logging.INFO,
            pathname=__file__,
            lineno=0,
            msg="token=%s and=%s",
            args=("only-one",),  # too few args → TypeError in getMessage
            exc_info=None,
        )
        assert flt.filter(record) is True
        # Message should still be scrubbed (no crash, no tokens).
        assert "token=%s" in str(record.msg)

    def test_filter_scrubs_args_and_msg(self) -> None:
        """Direct filter test — no logger machinery."""
        flt = RedactingFilter()
        record = logging.LogRecord(
            name="ya_passport_auth.direct",
            level=logging.INFO,
            pathname=__file__,
            lineno=0,
            msg="header=%s",
            args=("OAuth " + "f" * 40,),
            exc_info=None,
        )
        flt.filter(record)
        rendered = record.getMessage()
        assert "f" * 40 not in rendered
        assert "***" in rendered
