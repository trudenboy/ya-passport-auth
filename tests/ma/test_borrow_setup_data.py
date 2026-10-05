"""Borrowed credentials follow Music Assistant's setup-data storage contract.

Since MA 2.10 the Yandex Music provider persists (and rotates) its tokens in
setup data. ``Provider.get_setup_value`` returns the setup-data value when the
key is present — including an explicit ``None`` — and otherwise falls back to
the provider's config value. The fake owner below reproduces that documented
contract (music_assistant/models/provider.py ``Provider.get_setup_value``) so
the borrower is exercised against the same precedence the real owner uses.
"""

from __future__ import annotations

import pytest
from music_assistant_models.enums import ProviderType
from music_assistant_models.errors import LoginFailed

from ya_passport_auth import ResolvedCredentials, SecretStr
from ya_passport_auth.ma.borrow import BorrowedCredentialSource

_ABSENT = object()


class _SetupDataOwner:
    """Yandex Music owner exposing only MA's public setup-value accessor."""

    domain = "yandex_music"
    type = ProviderType.MUSIC

    def __init__(self, *, setup_data: dict[str, object], config: dict[str, object]) -> None:
        self.setup_data = setup_data
        self._config_values = config
        self.reads: list[str] = []

    @property
    def config(self) -> object:
        raise AssertionError("borrowers must read through get_setup_value, not owner.config")

    def get_setup_value(self, key: str, default: object = None) -> object:
        self.reads.append(key)
        if key in self.setup_data:
            return self.setup_data[key]
        return self._config_values.get(key, default)


class _Mass:
    def __init__(self, owner: object) -> None:
        self._owner = owner

    def get_provider(self, instance_id: str, *, return_unavailable: bool = False) -> object | None:
        return self._owner if instance_id == "ym-1" else None


def _plain(pair: tuple[SecretStr | None, SecretStr | None]) -> tuple[str | None, str | None]:
    return tuple(v.get_secret() if v is not None else None for v in pair)  # type: ignore[return-value]


_OLD_PAIR: dict[str, object] = {"token": "test-music-old", "x_token": "test-x-old"}


@pytest.mark.parametrize(
    ("setup_data", "config", "expected"),
    [
        pytest.param(
            {"token": "test-music-new", "x_token": "test-x-new"},
            _OLD_PAIR,
            ("test-music-new", "test-x-new"),
            id="setup-data-pair-wins-over-legacy-pair",
        ),
        pytest.param(
            {"token": "test-music-new", "x_token": "test-x-new"},
            {"x_token": "test-x-old"},
            ("test-music-new", "test-x-new"),
            id="setup-data-pair-wins-over-partial-legacy",
        ),
        pytest.param(
            {"token": None, "x_token": None},
            _OLD_PAIR,
            (None, None),
            id="explicit-clear-in-setup-data-is-respected",
        ),
        pytest.param(
            {},
            _OLD_PAIR,
            ("test-music-old", "test-x-old"),
            id="keys-absent-fall-back-to-config",
        ),
        pytest.param(
            {"x_token": "test-x-new"},
            _OLD_PAIR,
            ("test-music-old", "test-x-new"),
            id="per-key-precedence",
        ),
    ],
)
def test_read_tokens_follows_setup_data_contract(
    setup_data: dict[str, object],
    config: dict[str, object],
    expected: tuple[str | None, str | None],
) -> None:
    owner = _SetupDataOwner(setup_data=setup_data, config=config)

    pair = BorrowedCredentialSource(_Mass(owner), "ym-1").read_tokens()

    assert _plain(pair) == expected


def test_read_tokens_unwraps_secretstr_and_ignores_empty() -> None:
    owner = _SetupDataOwner(
        setup_data={"token": SecretStr("test-music-wrapped"), "x_token": ""}, config={}
    )

    pair = BorrowedCredentialSource(_Mass(owner), "ym-1").read_tokens()

    assert _plain(pair) == ("test-music-wrapped", None)


def test_custom_key_names_read_through_setup_data() -> None:
    owner = _SetupDataOwner(
        setup_data={"music_tok": "test-music-custom", "xtok": "test-x-custom"}, config={}
    )
    source = BorrowedCredentialSource(
        _Mass(owner), "ym-1", music_token_key="music_tok", x_token_key="xtok"
    )

    assert _plain(source.read_tokens()) == ("test-music-custom", "test-x-custom")


class TestResolveCredentials:
    async def test_reads_owner_once(self) -> None:
        owner = _SetupDataOwner(
            setup_data={"token": "test-music-new", "x_token": "test-x-new"}, config={}
        )

        creds = await BorrowedCredentialSource(_Mass(owner), "ym-1").resolve_credentials()

        assert creds == ResolvedCredentials(
            music_token=SecretStr("test-music-new"), x_token=SecretStr("test-x-new")
        )
        assert sorted(owner.reads) == ["token", "x_token"]

    async def test_maps_missing_credentials_to_login_failed(self) -> None:
        owner = _SetupDataOwner(setup_data={"token": None, "x_token": None}, config=_OLD_PAIR)

        with pytest.raises(LoginFailed, match="'ym-1' has no credentials"):
            await BorrowedCredentialSource(_Mass(owner), "ym-1").resolve_credentials()

    async def test_maps_rejected_only_music_token_to_login_failed(self) -> None:
        owner = _SetupDataOwner(setup_data={"token": "test-music-stale"}, config={})
        source = BorrowedCredentialSource(_Mass(owner), "ym-1")
        source.invalidate("test-music-stale")

        with pytest.raises(LoginFailed, match="'ym-1' has only a music token that was rejected"):
            await source.resolve_credentials()


def test_ma_package_reexports_resolved_credentials() -> None:
    from ya_passport_auth import ma  # noqa: PLC0415

    assert "ResolvedCredentials" in ma.__all__
    assert ma.ResolvedCredentials is ResolvedCredentials
