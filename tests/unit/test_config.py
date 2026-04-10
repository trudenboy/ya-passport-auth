"""Tests for ``ClientConfig``.

``ClientConfig`` is the single place where network, retry, and host
policy live. It must:

* be frozen (no runtime mutation of allow-lists or timeouts);
* have no way to disable TLS verification;
* validate numeric inputs so a caller cannot accidentally configure
  a zero-delay rate limiter or a negative timeout;
* default ``pinned_fingerprints`` to ``None`` (opt-in SPKI pinning).
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from ya_passport_auth.config import ClientConfig


class TestDefaults:
    def test_defaults_are_sensible(self) -> None:
        cfg = ClientConfig()
        assert cfg.total_timeout_seconds > 0
        assert cfg.connect_timeout_seconds > 0
        assert cfg.connect_timeout_seconds <= cfg.total_timeout_seconds
        assert cfg.min_request_interval_seconds > 0
        assert cfg.max_retries >= 0
        assert cfg.qr_poll_interval_seconds > 0
        assert cfg.qr_poll_total_timeout_seconds >= cfg.qr_poll_interval_seconds
        assert cfg.pinned_fingerprints is None
        assert isinstance(cfg.allowed_hosts, frozenset)
        assert "passport.yandex.ru" in cfg.allowed_hosts
        assert "oauth.mobile.yandex.net" in cfg.allowed_hosts

    def test_user_agent_is_non_empty(self) -> None:
        cfg = ClientConfig()
        assert cfg.user_agent
        assert "Yandex" in cfg.user_agent or "com.yandex" in cfg.user_agent


class TestImmutability:
    def test_frozen(self) -> None:
        cfg = ClientConfig()
        with pytest.raises(FrozenInstanceError):
            cfg.max_retries = 99  # type: ignore[misc]

    def test_allowed_hosts_is_frozenset(self) -> None:
        cfg = ClientConfig()
        with pytest.raises(AttributeError):
            cfg.allowed_hosts.add("evil.example.com")  # type: ignore[attr-defined]

    def test_no_verify_tls_attribute(self) -> None:
        """There must be no public way to disable TLS verification — even
        via a typo-tolerant attribute name. If someone later adds a
        ``verify_tls`` field it must default to True and be immutable."""
        cfg = ClientConfig()
        verify = getattr(cfg, "verify_tls", True)
        assert verify is True


class TestValidation:
    @pytest.mark.parametrize(
        "field",
        [
            "total_timeout_seconds",
            "connect_timeout_seconds",
            "min_request_interval_seconds",
            "qr_poll_interval_seconds",
            "qr_poll_total_timeout_seconds",
        ],
    )
    def test_rejects_non_positive_durations(self, field: str) -> None:
        with pytest.raises(ValueError, match=field):
            ClientConfig(**{field: 0.0})  # type: ignore[arg-type]
        with pytest.raises(ValueError, match=field):
            ClientConfig(**{field: -1.0})  # type: ignore[arg-type]

    def test_rejects_negative_max_retries(self) -> None:
        with pytest.raises(ValueError, match="max_retries"):
            ClientConfig(max_retries=-1)

    def test_rejects_connect_timeout_gt_total_timeout(self) -> None:
        with pytest.raises(ValueError, match="connect_timeout"):
            ClientConfig(
                total_timeout_seconds=5.0,
                connect_timeout_seconds=10.0,
            )

    def test_rejects_poll_interval_gt_total_timeout(self) -> None:
        with pytest.raises(ValueError, match="qr_poll"):
            ClientConfig(
                qr_poll_interval_seconds=10.0,
                qr_poll_total_timeout_seconds=5.0,
            )

    def test_rejects_empty_allowed_hosts(self) -> None:
        with pytest.raises(ValueError, match="allowed_hosts"):
            ClientConfig(allowed_hosts=frozenset())

    def test_rejects_empty_user_agent(self) -> None:
        with pytest.raises(ValueError, match="user_agent"):
            ClientConfig(user_agent="")


class TestPinnedFingerprints:
    def test_defaults_to_none(self) -> None:
        assert ClientConfig().pinned_fingerprints is None

    def test_accepts_hex_sha256(self) -> None:
        fp = "a" * 64
        cfg = ClientConfig(pinned_fingerprints=frozenset({fp}))
        assert cfg.pinned_fingerprints == frozenset({fp})

    def test_rejects_wrong_length_fingerprint(self) -> None:
        with pytest.raises(ValueError, match="fingerprint"):
            ClientConfig(pinned_fingerprints=frozenset({"deadbeef"}))

    def test_rejects_non_hex_fingerprint(self) -> None:
        with pytest.raises(ValueError, match="fingerprint"):
            ClientConfig(pinned_fingerprints=frozenset({"z" * 64}))

    def test_rejects_empty_set(self) -> None:
        # Empty set is ambiguous — either `None` (opt-out) or a list — reject
        # it so the caller is explicit.
        with pytest.raises(ValueError, match="pinned_fingerprints"):
            ClientConfig(pinned_fingerprints=frozenset())
