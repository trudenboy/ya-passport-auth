"""Tests for the ``YaPassportError`` hierarchy.

Each exception must:

* inherit from the single root ``YaPassportError`` so callers can
  catch everything from the library with one ``except`` clause;
* expose ``status_code`` and ``endpoint`` attributes (either a value
  or ``None``);
* never accept ``SecretStr``/``Credentials`` in the constructor —
  there is no safe way to render them and their presence would risk
  leaking tokens into tracebacks (T1).
"""

from __future__ import annotations

import pytest

from ya_passport_auth.credentials import Credentials, SecretStr
from ya_passport_auth.exceptions import (
    AuthFailedError,
    CsrfExtractionError,
    InvalidCredentialsError,
    NetworkError,
    QRPendingError,
    QRTimeoutError,
    RateLimitedError,
    UnexpectedHostError,
    YaPassportError,
)


@pytest.fixture(
    params=[
        YaPassportError,
        NetworkError,
        UnexpectedHostError,
        AuthFailedError,
        InvalidCredentialsError,
        CsrfExtractionError,
        RateLimitedError,
        QRPendingError,
        QRTimeoutError,
    ],
)
def exc_cls(request: pytest.FixtureRequest) -> type[YaPassportError]:
    return request.param  # type: ignore[no-any-return]


class TestHierarchy:
    def test_all_subclass_root(self, exc_cls: type[YaPassportError]) -> None:
        assert issubclass(exc_cls, YaPassportError)

    def test_network_subtree(self) -> None:
        assert issubclass(UnexpectedHostError, NetworkError)

    def test_auth_subtree(self) -> None:
        for sub in (
            InvalidCredentialsError,
            CsrfExtractionError,
            RateLimitedError,
            QRPendingError,
            QRTimeoutError,
        ):
            assert issubclass(sub, AuthFailedError), sub

    def test_auth_and_network_are_disjoint(self) -> None:
        assert not issubclass(NetworkError, AuthFailedError)
        assert not issubclass(AuthFailedError, NetworkError)


class TestConstruction:
    def test_default_endpoint_is_none(self, exc_cls: type[YaPassportError]) -> None:
        err = exc_cls("boom")
        # status_code may come from the class default (e.g. 429 for
        # RateLimitedError); endpoint must always default to None.
        assert err.endpoint is None
        assert err.status_code == exc_cls.default_status_code
        assert "boom" in str(err)

    def test_fields_round_trip(self, exc_cls: type[YaPassportError]) -> None:
        err = exc_cls("boom", status_code=429, endpoint="https://oauth.yandex.ru/token")
        assert err.status_code == 429
        assert err.endpoint == "https://oauth.yandex.ru/token"

    def test_endpoint_strips_query_and_fragment(self, exc_cls: type[YaPassportError]) -> None:
        """Query strings and fragments can carry secrets (e.g. ``?token=``)
        so the exception normalizes to scheme+host+path only.
        """
        err = exc_cls(
            "boom",
            endpoint="https://oauth.yandex.ru/token?password=hunter2#x",
        )
        assert err.endpoint == "https://oauth.yandex.ru/token"


class TestNoSecretLeakage:
    def test_message_rejects_secretstr(self) -> None:
        with pytest.raises(TypeError, match="SecretStr"):
            YaPassportError(SecretStr("x-token-abc"))  # type: ignore[arg-type]

    def test_message_rejects_credentials(self) -> None:
        creds = Credentials(x_token=SecretStr("x-token-abc"))
        with pytest.raises(TypeError, match="Credentials"):
            YaPassportError(creds)  # type: ignore[arg-type]

    def test_subclass_also_rejects_secretstr(self) -> None:
        with pytest.raises(TypeError):
            RateLimitedError(SecretStr("x-token-abc"))  # type: ignore[arg-type]


class TestRateLimitedHelpers:
    def test_status_code_defaults_to_429(self) -> None:
        err = RateLimitedError("rate limited")
        assert err.status_code == 429


class TestQRControlFlow:
    def test_qr_pending_is_not_an_error_to_the_user(self) -> None:
        """``QRPendingError`` is a control-flow signal — it should still be
        a proper exception subclass so ``except`` catches it, but it must
        be cheap to raise."""
        err = QRPendingError("still waiting")
        assert isinstance(err, YaPassportError)
        assert isinstance(err, AuthFailedError)
