"""Tests for the OAuth Device Flow."""

from __future__ import annotations

import re
from collections.abc import AsyncGenerator

import aiohttp
import pytest
from aioresponses import aioresponses
from yarl import URL

from ya_passport_auth.config import ClientConfig
from ya_passport_auth.constants import (
    DEVICE_CODE_URL,
    OAUTH_TOKEN_URL,
    PASSPORT_CLIENT_ID,
    PASSPORT_CLIENT_SECRET,
)
from ya_passport_auth.credentials import SecretStr
from ya_passport_auth.exceptions import (
    AuthFailedError,
    DeviceCodeTimeoutError,
    InvalidCredentialsError,
    NetworkError,
)
from ya_passport_auth.flows.device_code import DeviceCodeFlow, PollOutcome
from ya_passport_auth.http import SafeHttpClient
from ya_passport_auth.models import DeviceCodeSession, OAuthTokens
from ya_passport_auth.rate_limit import AsyncMinDelayLimiter

_JSON_CT = {"Content-Type": "application/json"}

_TEST_DEVICE_CODE = "test-device-code-0123456789abcdef"
_TEST_USER_CODE = "abcd1234"
_TEST_VERIFICATION_URL = "https://ya.ru/device"
_TEST_ACCESS_TOKEN = "test-access-token-0123456789abcdef"
_TEST_REFRESH_TOKEN = "test-refresh-token-0123456789abcdef"


@pytest.fixture
def config() -> ClientConfig:
    return ClientConfig(min_request_interval_seconds=0.001)


@pytest.fixture
async def session() -> AsyncGenerator[aiohttp.ClientSession, None]:
    jar = aiohttp.CookieJar(unsafe=True)
    async with aiohttp.ClientSession(cookie_jar=jar) as s:
        yield s


@pytest.fixture
def http(session: aiohttp.ClientSession, config: ClientConfig) -> SafeHttpClient:
    limiter = AsyncMinDelayLimiter(min_interval_seconds=0.001)
    return SafeHttpClient(session=session, config=config, limiter=limiter)


@pytest.fixture
def flow(http: SafeHttpClient) -> DeviceCodeFlow:
    return DeviceCodeFlow(http=http)


def _form_field(kwargs: dict[str, object], field: str) -> str:
    data = kwargs["data"]
    assert isinstance(data, dict)
    value = data[field]
    assert isinstance(value, str)
    return value


# ------------------------------------------------------------------ #
# request_code
# ------------------------------------------------------------------ #
class TestRequestCode:
    async def test_success(self, flow: DeviceCodeFlow) -> None:
        with aioresponses() as m:
            m.post(
                DEVICE_CODE_URL,
                status=200,
                payload={
                    "device_code": _TEST_DEVICE_CODE,
                    "user_code": _TEST_USER_CODE,
                    "verification_url": _TEST_VERIFICATION_URL,
                    "expires_in": 300,
                    "interval": 5,
                },
                headers=_JSON_CT,
            )
            code = await flow.request_code()

        assert isinstance(code, DeviceCodeSession)
        assert code.device_code.get_secret() == _TEST_DEVICE_CODE
        assert code.user_code == _TEST_USER_CODE
        assert code.verification_url == _TEST_VERIFICATION_URL
        assert code.expires_in == 300
        assert code.interval == 5

    async def test_custom_device_id_and_name(self, flow: DeviceCodeFlow) -> None:
        with aioresponses() as m:
            m.post(
                DEVICE_CODE_URL,
                status=200,
                payload={
                    "device_code": _TEST_DEVICE_CODE,
                    "user_code": _TEST_USER_CODE,
                    "verification_url": _TEST_VERIFICATION_URL,
                    "expires_in": 300,
                    "interval": 5,
                },
                headers=_JSON_CT,
            )
            await flow.request_code(device_id="my-device-id", device_name="my-device-name")

            calls = m.requests[("POST", URL(DEVICE_CODE_URL))]

        assert _form_field(calls[0].kwargs, "device_id") == "my-device-id"
        assert _form_field(calls[0].kwargs, "device_name") == "my-device-name"
        assert _form_field(calls[0].kwargs, "client_id") == PASSPORT_CLIENT_ID

    async def test_generated_device_id_format(self, flow: DeviceCodeFlow) -> None:
        with aioresponses() as m:
            m.post(
                DEVICE_CODE_URL,
                status=200,
                payload={
                    "device_code": _TEST_DEVICE_CODE,
                    "user_code": _TEST_USER_CODE,
                    "verification_url": _TEST_VERIFICATION_URL,
                    "expires_in": 300,
                    "interval": 5,
                },
                headers=_JSON_CT,
            )
            await flow.request_code()
            calls = m.requests[("POST", URL(DEVICE_CODE_URL))]

        generated = _form_field(calls[0].kwargs, "device_id")
        assert re.fullmatch(r"[A-Za-z0-9]{10}", generated)

    async def test_missing_field_raises(self, flow: DeviceCodeFlow) -> None:
        with aioresponses() as m:
            m.post(
                DEVICE_CODE_URL,
                status=200,
                payload={
                    "user_code": _TEST_USER_CODE,
                    "verification_url": _TEST_VERIFICATION_URL,
                    "expires_in": 300,
                    "interval": 5,
                },
                headers=_JSON_CT,
            )
            with pytest.raises(AuthFailedError, match="device_code"):
                await flow.request_code()

    async def test_non_integer_interval_raises(self, flow: DeviceCodeFlow) -> None:
        with aioresponses() as m:
            m.post(
                DEVICE_CODE_URL,
                status=200,
                payload={
                    "device_code": _TEST_DEVICE_CODE,
                    "user_code": _TEST_USER_CODE,
                    "verification_url": _TEST_VERIFICATION_URL,
                    "expires_in": 300,
                    "interval": "5",
                },
                headers=_JSON_CT,
            )
            with pytest.raises(AuthFailedError, match="interval"):
                await flow.request_code()

    async def test_error_response_raises(self, flow: DeviceCodeFlow) -> None:
        with aioresponses() as m:
            m.post(
                DEVICE_CODE_URL,
                status=400,
                payload={
                    "error": "invalid_client",
                    "error_description": "Client not found",
                },
                headers=_JSON_CT,
            )
            with pytest.raises(AuthFailedError, match="invalid_client"):
                await flow.request_code()


# ------------------------------------------------------------------ #
# poll_token
# ------------------------------------------------------------------ #
class TestPollToken:
    async def test_success(self, flow: DeviceCodeFlow) -> None:
        with aioresponses() as m:
            m.post(
                OAUTH_TOKEN_URL,
                status=200,
                payload={
                    "access_token": _TEST_ACCESS_TOKEN,
                    "refresh_token": _TEST_REFRESH_TOKEN,
                    "expires_in": 31_536_000,
                    "token_type": "bearer",
                },
                headers=_JSON_CT,
            )
            tokens = await flow.poll_token(SecretStr(_TEST_DEVICE_CODE))

        assert isinstance(tokens, OAuthTokens)
        assert tokens.access_token.get_secret() == _TEST_ACCESS_TOKEN
        assert tokens.refresh_token.get_secret() == _TEST_REFRESH_TOKEN
        assert tokens.expires_in == 31_536_000

    async def test_success_sends_client_credentials(self, flow: DeviceCodeFlow) -> None:
        with aioresponses() as m:
            m.post(
                OAUTH_TOKEN_URL,
                status=200,
                payload={
                    "access_token": _TEST_ACCESS_TOKEN,
                    "refresh_token": _TEST_REFRESH_TOKEN,
                    "expires_in": 1,
                },
                headers=_JSON_CT,
            )
            await flow.poll_token(SecretStr(_TEST_DEVICE_CODE))
            calls = m.requests[("POST", URL(OAUTH_TOKEN_URL))]

        assert _form_field(calls[0].kwargs, "grant_type") == "device_code"
        assert _form_field(calls[0].kwargs, "code") == _TEST_DEVICE_CODE
        assert _form_field(calls[0].kwargs, "client_id") == PASSPORT_CLIENT_ID
        assert _form_field(calls[0].kwargs, "client_secret") == PASSPORT_CLIENT_SECRET

    async def test_authorization_pending_returns_pending(self, flow: DeviceCodeFlow) -> None:
        with aioresponses() as m:
            m.post(
                OAUTH_TOKEN_URL,
                status=400,
                payload={
                    "error": "authorization_pending",
                    "error_description": "Authorization not yet granted",
                },
                headers=_JSON_CT,
            )
            result = await flow.poll_token(SecretStr(_TEST_DEVICE_CODE))

        assert result is PollOutcome.PENDING

    async def test_slow_down_returns_slow_down(self, flow: DeviceCodeFlow) -> None:
        with aioresponses() as m:
            m.post(
                OAUTH_TOKEN_URL,
                status=400,
                payload={"error": "slow_down"},
                headers=_JSON_CT,
            )
            result = await flow.poll_token(SecretStr(_TEST_DEVICE_CODE))

        assert result is PollOutcome.SLOW_DOWN

    async def test_expired_token_raises_timeout(self, flow: DeviceCodeFlow) -> None:
        with aioresponses() as m:
            m.post(
                OAUTH_TOKEN_URL,
                status=400,
                payload={"error": "expired_token"},
                headers=_JSON_CT,
            )
            with pytest.raises(DeviceCodeTimeoutError):
                await flow.poll_token(SecretStr(_TEST_DEVICE_CODE))

    async def test_access_denied_raises_invalid_credentials(self, flow: DeviceCodeFlow) -> None:
        with aioresponses() as m:
            m.post(
                OAUTH_TOKEN_URL,
                status=400,
                payload={"error": "access_denied"},
                headers=_JSON_CT,
            )
            with pytest.raises(InvalidCredentialsError, match="denied"):
                await flow.poll_token(SecretStr(_TEST_DEVICE_CODE))

    @pytest.mark.parametrize(
        "error_value",
        ["invalid_client", "invalid_grant", "unknown_error"],
    )
    async def test_other_errors_raise_auth_failed(
        self, flow: DeviceCodeFlow, error_value: str
    ) -> None:
        with aioresponses() as m:
            m.post(
                OAUTH_TOKEN_URL,
                status=400,
                payload={"error": error_value},
                headers=_JSON_CT,
            )
            with pytest.raises(AuthFailedError, match=error_value):
                await flow.poll_token(SecretStr(_TEST_DEVICE_CODE))

    async def test_unexpected_shape_raises(self, flow: DeviceCodeFlow) -> None:
        with aioresponses() as m:
            m.post(
                OAUTH_TOKEN_URL,
                status=200,
                payload={"token_type": "bearer"},
                headers=_JSON_CT,
            )
            with pytest.raises(AuthFailedError, match="unexpected"):
                await flow.poll_token(SecretStr(_TEST_DEVICE_CODE))

    async def test_malformed_tokens_raise(self, flow: DeviceCodeFlow) -> None:
        with aioresponses() as m:
            m.post(
                OAUTH_TOKEN_URL,
                status=200,
                payload={
                    "access_token": _TEST_ACCESS_TOKEN,
                    "refresh_token": "",
                    "expires_in": 100,
                },
                headers=_JSON_CT,
            )
            with pytest.raises(AuthFailedError, match="unexpected"):
                await flow.poll_token(SecretStr(_TEST_DEVICE_CODE))

    async def test_network_error_propagates(self, flow: DeviceCodeFlow) -> None:
        with aioresponses() as m:
            m.post(
                OAUTH_TOKEN_URL,
                exception=aiohttp.ClientError("connection reset"),
            )
            with pytest.raises(NetworkError):
                await flow.poll_token(SecretStr(_TEST_DEVICE_CODE))


# ------------------------------------------------------------------ #
# refresh
# ------------------------------------------------------------------ #
class TestRefresh:
    async def test_success(self, flow: DeviceCodeFlow) -> None:
        new_access = "new-access-token-abcdef0123456789"
        new_refresh = "new-refresh-token-abcdef0123456789"
        with aioresponses() as m:
            m.post(
                OAUTH_TOKEN_URL,
                status=200,
                payload={
                    "access_token": new_access,
                    "refresh_token": new_refresh,
                    "expires_in": 31_536_000,
                },
                headers=_JSON_CT,
            )
            tokens = await flow.refresh(SecretStr(_TEST_REFRESH_TOKEN))
            calls = m.requests[("POST", URL(OAUTH_TOKEN_URL))]

        assert tokens.access_token.get_secret() == new_access
        assert tokens.refresh_token.get_secret() == new_refresh
        assert _form_field(calls[0].kwargs, "grant_type") == "refresh_token"
        assert _form_field(calls[0].kwargs, "refresh_token") == _TEST_REFRESH_TOKEN

    async def test_invalid_grant_raises_invalid_credentials(self, flow: DeviceCodeFlow) -> None:
        with aioresponses() as m:
            m.post(
                OAUTH_TOKEN_URL,
                status=400,
                payload={"error": "invalid_grant"},
                headers=_JSON_CT,
            )
            with pytest.raises(InvalidCredentialsError, match="rejected"):
                await flow.refresh(SecretStr(_TEST_REFRESH_TOKEN))

    async def test_other_error_raises_auth_failed(self, flow: DeviceCodeFlow) -> None:
        with aioresponses() as m:
            m.post(
                OAUTH_TOKEN_URL,
                status=400,
                payload={"error": "invalid_client"},
                headers=_JSON_CT,
            )
            with pytest.raises(AuthFailedError, match="invalid_client"):
                await flow.refresh(SecretStr(_TEST_REFRESH_TOKEN))

    async def test_unexpected_shape_raises(self, flow: DeviceCodeFlow) -> None:
        with aioresponses() as m:
            m.post(
                OAUTH_TOKEN_URL,
                status=200,
                payload={"token_type": "bearer"},
                headers=_JSON_CT,
            )
            with pytest.raises(AuthFailedError, match="unexpected"):
                await flow.refresh(SecretStr(_TEST_REFRESH_TOKEN))


# ------------------------------------------------------------------ #
# Repr redaction
# ------------------------------------------------------------------ #
class TestRepr:
    def test_device_code_session_repr_redacts(self) -> None:
        session = DeviceCodeSession(
            device_code=SecretStr(_TEST_DEVICE_CODE),
            user_code=_TEST_USER_CODE,
            verification_url=_TEST_VERIFICATION_URL,
            expires_in=300,
            interval=5,
        )
        rendered = repr(session)
        assert _TEST_DEVICE_CODE not in rendered
        assert _TEST_VERIFICATION_URL in rendered
        assert "expires_in=300" in rendered

    def test_oauth_tokens_repr_redacts(self) -> None:
        tokens = OAuthTokens(
            access_token=SecretStr(_TEST_ACCESS_TOKEN),
            refresh_token=SecretStr(_TEST_REFRESH_TOKEN),
            expires_in=31_536_000,
        )
        rendered = repr(tokens)
        assert _TEST_ACCESS_TOKEN not in rendered
        assert _TEST_REFRESH_TOKEN not in rendered
        assert "***" in rendered
        assert "expires_in=31536000" in rendered
