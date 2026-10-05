"""Borrowed credentials: one Yandex account shared across MA providers.

Extracted from the ``yandex_ynison`` plugin's borrow mode (its spec 0004).
A provider links to a configured ``yandex_music`` instance and *borrows* its
tokens instead of running its own login. The owner (the yandex_music
instance) is the only party that persists and rotates credentials; borrowers
only read them. The resolution logic itself lives in the framework-neutral
:mod:`ya_passport_auth.sharing`; this module adapts it to Music Assistant:
it resolves and validates the linked owner, reads tokens through the owner's
setup data (MA 2.10+), and maps outcomes to MA error types.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, Protocol, cast

from music_assistant_models.enums import ProviderType
from music_assistant_models.errors import LoginFailed, ResourceTemporarilyUnavailable

from ya_passport_auth import SecretStr
from ya_passport_auth.exceptions import NoUsableCredentialsError
from ya_passport_auth.sharing import (
    MUSIC_TOKEN_TTL_S,
    ResolvedCredentials,
    SharedTokenResolver,
    TokenSnapshot,
)

from .tokens import refresh_music_token

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import MappingProxyType

__all__ = [
    "BORROW_SOURCE_OWN",
    "MUSIC_TOKEN_TTL_S",
    "BorrowedCredentialSource",
    "ResolvedCredentials",
    "list_yandex_music_instances",
]

# Sentinel config value for "use this provider's own login" in the account
# source dropdown (matches the value the yandex_ynison plugin established).
BORROW_SOURCE_OWN: Final = "__own__"


class _SetupValueOwner(Protocol):
    """The part of an MA provider instance a borrower relies on."""

    domain: str
    type: ProviderType

    def get_setup_value(self, key: str, default: object = None) -> object:
        """Return a setup-data value, falling back to the provider config."""
        ...


def list_yandex_music_instances(mass: object) -> list[tuple[str, str]]:
    """List configured yandex_music provider instances.

    Args:
        mass: The MusicAssistant instance (reads ``config.get("providers")``).

    Returns:
        ``(instance_id, display_name)`` pairs for the account-source dropdown.
    """
    instances: list[tuple[str, str]] = []
    config = getattr(mass, "config", None)
    get = getattr(config, "get", None)
    if not callable(get):
        return instances
    raw_providers = cast("MappingProxyType[str, object]", get("providers", {}))
    for instance_id, prov_conf in raw_providers.items():
        if not isinstance(prov_conf, dict) or prov_conf.get("domain") != "yandex_music":
            continue
        display_name = prov_conf.get("name") or instance_id
        instances.append((str(instance_id), str(display_name)))
    return instances


def _secret_or_none(value: object) -> SecretStr | None:
    """Wrap a stored value as SecretStr; unwrap values already wrapped.

    ``str()`` on a SecretStr would yield the redaction placeholder and
    silently corrupt the token — unwrap explicitly instead.
    """
    if isinstance(value, SecretStr):
        return value if value.get_secret() else None
    return SecretStr(str(value)) if value else None


class _LinkedOwnerReader:
    """Read the linked yandex_music instance's tokens from its setup data."""

    def __init__(
        self, mass: object, instance_id: str, music_token_key: str, x_token_key: str
    ) -> None:
        self._mass = mass
        self._instance_id = instance_id
        self._music_token_key = music_token_key
        self._x_token_key = x_token_key

    def read_now(self) -> TokenSnapshot:
        owner = self._resolve_owner()
        return TokenSnapshot(
            music_token=_secret_or_none(owner.get_setup_value(self._music_token_key)),
            x_token=_secret_or_none(owner.get_setup_value(self._x_token_key)),
        )

    async def read_tokens(self) -> TokenSnapshot:
        return self.read_now()

    def _resolve_owner(self) -> _SetupValueOwner:
        get_provider = getattr(self._mass, "get_provider", None)
        owner = (
            get_provider(self._instance_id, return_unavailable=True)
            if callable(get_provider)
            else None
        )
        if owner is None:
            raise ResourceTemporarilyUnavailable(
                f"Linked Yandex Music instance '{self._instance_id}' is not loaded. "
                "Check that the Yandex Music provider is enabled and configured."
            )
        # Guard against a stale/manually-edited instance id pointing at a
        # non-YM provider — otherwise reading unrelated keys yields a
        # misleading "no credentials" error further down.
        domain = getattr(owner, "domain", None)
        provider_type = getattr(owner, "type", None)
        if domain != "yandex_music" or provider_type != ProviderType.MUSIC:
            raise LoginFailed(
                f"Linked provider instance '{self._instance_id}' is not a Yandex Music "
                f"music provider (domain={domain!r}, type={provider_type!r}). "
                "Re-select the Yandex Music source in this provider's configuration."
            )
        return cast("_SetupValueOwner", owner)


class BorrowedCredentialSource:
    """Read-only view of a linked yandex_music instance's credentials.

    Args:
        mass: The MusicAssistant instance.
        instance_id: The linked yandex_music provider instance id.
        music_token_key: The owner's setup key for the music-scoped token
            (yandex_music persists it as ``"token"``).
        x_token_key: The owner's setup key for the long-lived x_token.
        now: Monotonic-clock seam for tests.
    """

    def __init__(
        self,
        mass: object,
        instance_id: str,
        *,
        music_token_key: str = "token",  # noqa: S107 — setup KEY name, not a secret
        x_token_key: str = "x_token",  # noqa: S107
        now: Callable[[], float] | None = None,
    ) -> None:
        self._mass = mass
        self.instance_id = instance_id
        self._reader = _LinkedOwnerReader(mass, instance_id, music_token_key, x_token_key)
        self._resolver = (
            SharedTokenResolver(self._reader, mint=_mint_music_token)
            if now is None
            else SharedTokenResolver(self._reader, mint=_mint_music_token, now=now)
        )

    def read_tokens(self) -> tuple[SecretStr | None, SecretStr | None]:
        """Read ``(music_token, x_token)`` from the owner's setup data.

        Raises:
            ResourceTemporarilyUnavailable: The linked instance is not
                loaded (yet) — a startup load-ordering condition; retry
                later instead of treating it as an auth failure.
            LoginFailed: The configured id points at something that is not a
                yandex_music music provider.
        """
        snapshot = self._reader.read_now()
        return snapshot.music_token, snapshot.x_token

    async def resolve_credentials(self) -> ResolvedCredentials:
        """Return a usable music token and the x_token from one owner read.

        Never writes to the owner: when it has no usable music token, one is
        minted in memory from its x_token and cached for
        :data:`MUSIC_TOKEN_TTL_S`.

        Raises:
            LoginFailed: The owner holds no usable credentials, or Yandex
                explicitly rejected the x_token.
            ResourceTemporarilyUnavailable: The owner is not loaded yet, or
                a transient Passport failure.
        """
        try:
            return await self._resolver.resolve()
        except NoUsableCredentialsError as err:
            if err.reason == "rejected_without_x_token":
                raise LoginFailed(
                    f"Linked Yandex Music instance '{self.instance_id}' has only a music "
                    "token that was rejected, and no x_token to mint a fresh one from. "
                    "Re-authenticate the Yandex Music provider."
                ) from None
            raise LoginFailed(
                f"Linked Yandex Music instance '{self.instance_id}' has no credentials. "
                "Authenticate the Yandex Music provider (and enable Remember session) first."
            ) from None

    async def resolve_music_token(self) -> SecretStr:
        """Return a usable music token without writing to the owner.

        Raises:
            LoginFailed: The owner holds no usable credentials, or Yandex
                explicitly rejected the x_token.
            ResourceTemporarilyUnavailable: The owner is not loaded yet, or
                a transient Passport failure.
        """
        return (await self.resolve_credentials()).music_token

    def invalidate(self, token: str | SecretStr) -> None:
        """Mark *token* stale after a 401 — pass whichever token failed.

        Args:
            token: The token that Yandex rejected (x_token, minted music
                token, or the owner's persisted music token).
        """
        self._resolver.invalidate(token)


async def _mint_music_token(x_token: SecretStr) -> SecretStr:
    # Looked up at call time so the MA-mapped refresh (and test patches of
    # this module's ``refresh_music_token``) apply.
    return await refresh_music_token(x_token)
