"""Silent credential-refresh cascade shared by the MA yandex providers.

Generalized from the ``yandex_station`` provider's session-init cascade and
the ``yandex_music`` provider's refresh-token rotation. The cascade owns the
*token* logic only; everything provider-specific (HTTP session lifecycle,
cookie/CSRF refresh, live-session token application) is injected as hooks.

Cascade steps (each step persists rotated values on success):

1. Fast-path: when both ``music_token`` and ``x_token`` are present, the
   optional ``fast_path`` hook validates the stored tokens as-is.
2. If step 1 fails and ``x_token`` exists → ask Passport for a fresh
   music_token.
3. If step 2 fails terminally and ``refresh_token`` exists (Device Flow
   only) → silently rotate the full credential triple.
4. Terminal: clear all three keys and return ``False`` so the caller can
   surface a re-login prompt.

"Remember session" is respected: when it is off, steps 2-4 are skipped
because x_token/refresh_token are not stored for throw-away sessions.

Rotation safety: ``refresh_token`` is single-use (rotates server-side), so
all rotation goes through one internal lock — concurrent 401 storms trigger
a single rotation (contract from the ``yandex_ynison`` provider's spec 0004).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from music_assistant_models.errors import LoginFailed, ResourceTemporarilyUnavailable

from ya_passport_auth import SecretStr

from .tokens import refresh_credentials, refresh_music_token

if TYPE_CHECKING:
    from ya_passport_auth import Credentials

__all__ = ["CascadeHooks", "CredentialCascade", "KeySpec"]

_LOGGER = logging.getLogger(__name__)

GetValue = Callable[[str], object]
SetValue = Callable[[str, str | None], None]
BoolHook = Callable[[], Awaitable[bool]]
CredsHook = Callable[["Credentials"], Awaitable[None]]
TokenHook = Callable[[SecretStr], Awaitable[None]]


@dataclass(frozen=True, slots=True)
class KeySpec:
    """Names of the provider's persisted credential config keys.

    Persisted key names intentionally differ across providers (renames would
    invalidate user configs) — the cascade is parameterized instead.

    Args:
        x_token: Key holding the long-lived Passport session token.
        music_token: Key holding the music-scoped OAuth token.
        refresh_token: Key holding the Device Flow refresh token.
        remember_session: Boolean key gating long-lived token storage.
    """

    # Values are config KEY NAMES, not secrets (S105 false positives).
    x_token: str = "x_token"  # noqa: S105
    music_token: str = "music_token"  # noqa: S105
    refresh_token: str = "refresh_token"  # noqa: S105
    remember_session: str = "remember_session"


@dataclass(frozen=True, slots=True)
class CascadeHooks:
    """Provider-specific behavior injected into the cascade.

    Args:
        fast_path: Validate the stored tokens as-is (e.g. yandex_station
            logs in with the stored x_token and confirms a usable
            music_token). ``None`` skips straight to refresh.
        apply_music_token: Apply a freshly refreshed music token to the
            provider's live session object.
        apply_credentials: Apply a fully rotated credential triple to the
            provider's live session object.
        post_refresh: Provider-side finalization after a successful token
            refresh/rotation (e.g. yandex_station re-grabs Quasar session
            cookies). Returning ``False`` fails that cascade step.
        on_failure: Cleanup when the cascade gives up or propagates a
            transient error (e.g. close the provider's HTTP session).
    """

    fast_path: BoolHook | None = None
    apply_music_token: TokenHook | None = None
    apply_credentials: CredsHook | None = None
    post_refresh: BoolHook | None = None
    on_failure: Callable[[], Awaitable[None]] | None = None


class CredentialCascade:
    """Token-refresh engine over provider-persisted credentials.

    Args:
        keys: The provider's config key names.
        get_value: Read a persisted config value by key.
        set_value: Persist a config value by key (``None`` clears it);
            encryption is the provider's responsibility.
        hooks: Provider-specific behavior (see :class:`CascadeHooks`).
        logger: Provider logger; defaults to this module's logger.
    """

    def __init__(
        self,
        *,
        keys: KeySpec,
        get_value: GetValue,
        set_value: SetValue,
        hooks: CascadeHooks | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self._keys = keys
        self._get = get_value
        self._set = set_value
        self._hooks = hooks or CascadeHooks()
        self._log = logger or _LOGGER
        # Serializes every rotation: refresh_token is single-use, so
        # concurrent 401s must trigger exactly one rotation.
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------ #
    # Reads
    # ------------------------------------------------------------------ #
    def _secret(self, key: str) -> SecretStr | None:
        value = self._get(key)
        return SecretStr(value) if isinstance(value, str) and value else None

    @property
    def remember_session(self) -> bool:
        """Whether long-lived tokens are stored (defaults to True when unset)."""
        value = self._get(self._keys.remember_session)
        return True if value is None else bool(value)

    # ------------------------------------------------------------------ #
    # Cascade
    # ------------------------------------------------------------------ #
    async def initialize(self) -> bool:
        """Run the full startup cascade.

        Returns:
            ``True`` when a working credential set is established, ``False``
            when the user must re-authenticate.

        Raises:
            ResourceTemporarilyUnavailable: Transient Passport failure —
                stored credentials are preserved so a later retry can succeed.
        """
        async with self._lock:
            music_token = self._secret(self._keys.music_token)
            x_token = self._secret(self._keys.x_token)
            refresh_token = self._secret(self._keys.refresh_token)

            if music_token is None and x_token is None:
                self._log.warning("No credentials configured")
                return False

            if (
                music_token is not None
                and x_token is not None
                and self._hooks.fast_path is not None
            ):
                if await self._run_fast_path():
                    return True
            elif music_token is not None and x_token is not None:
                # No validation hook — trust the stored pair as-is.
                return True

            # No silent-refresh path available when either Remember session
            # is off (x_token/refresh_token weren't persisted) or x_token is
            # missing. Run with the music_token as the only credential.
            if not self.remember_session:
                return await self._finish_without_refresh(music_token is not None, "disabled")
            if x_token is None:
                return await self._finish_without_refresh(music_token is not None, "no_x_token")

            return await self._silent_refresh_cascade(x_token, refresh_token)

    async def silent_reauth(self) -> bool:
        """Attempt a silent re-auth after a runtime 401/403.

        One-retry semantics are the caller's job — this method itself runs
        the refresh cascade every time it's called (serialized internally).

        Returns:
            ``True`` when credentials were rotated and the caller can retry
            its operation; ``False`` when silent refresh isn't possible.
        """
        async with self._lock:
            # Read inside the lock so we pick up values rotated by a prior
            # waiter instead of acting on stale credentials.
            x_token = self._secret(self._keys.x_token)
            refresh_token = self._secret(self._keys.refresh_token)
            if x_token is None:
                return False
            try:
                new_music_token = await refresh_music_token(x_token)
            except LoginFailed:
                return await self._try_rotation(x_token, refresh_token)

            self._set(self._keys.music_token, new_music_token.get_secret())
            if self._hooks.apply_music_token is not None:
                await self._hooks.apply_music_token(new_music_token)

            # Provider-side finalization (e.g. cookie refresh). If it fails
            # (expired x_token), fall back to refresh_token rotation —
            # otherwise the caller would retry with stale state and 401 again.
            if self._hooks.post_refresh is None:
                return True
            try:
                if await self._hooks.post_refresh():
                    return True
                self._log.debug("post_refresh after silent reauth returned False")
            except Exception:
                self._log.debug("post_refresh after silent reauth failed", exc_info=True)
            return await self._try_rotation(x_token, refresh_token)

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #
    async def _run_fast_path(self) -> bool:
        if self._hooks.fast_path is None:
            return False
        try:
            return await self._hooks.fast_path()
        except Exception:
            self._log.exception("Error validating stored credentials")
            return False

    async def _finish_without_refresh(self, has_music_token: bool, reason: str) -> bool:
        msg_reason = (
            "Remember session disabled"
            if reason == "disabled"
            else "no x_token available for silent refresh"
        )
        if has_music_token:
            self._log.info("%s — running with music_token only", msg_reason)
            return True
        self._log.warning("%s and no music_token available — cannot login", msg_reason)
        await self._fail()
        return False

    async def _silent_refresh_cascade(
        self, x_token: SecretStr, refresh_token: SecretStr | None
    ) -> bool:
        try:
            new_music_token = await refresh_music_token(x_token)
        except LoginFailed:
            return await self._handle_x_token_expired(x_token, refresh_token)
        except ResourceTemporarilyUnavailable:
            # Transient failure — let it propagate so creds aren't wiped.
            await self._fail()
            raise
        except asyncio.CancelledError:
            raise
        except Exception as err:
            self._log.warning("Session token refresh failed (network): %s", type(err).__name__)
            await self._fail()
            raise ResourceTemporarilyUnavailable(
                "Unable to refresh music token right now. Please try again later."
            ) from err

        self._set(self._keys.music_token, new_music_token.get_secret())
        if self._hooks.apply_music_token is not None:
            await self._hooks.apply_music_token(new_music_token)
        if self._hooks.post_refresh is None or await self._hooks.post_refresh():
            self._log.info("Refreshed music token from session token")
            return True
        await self._fail()
        return False

    async def _handle_x_token_expired(
        self, x_token: SecretStr, refresh_token: SecretStr | None
    ) -> bool:
        if refresh_token is not None:
            try:
                await self._rotate_via_refresh_token(x_token, refresh_token)
            except LoginFailed:
                await self._fail()
                return False
            except ResourceTemporarilyUnavailable:
                # Transient — don't wipe creds, let the caller retry later.
                await self._fail()
                raise
            else:
                return True
        self._log.warning("Session token expired, clearing credentials")
        self._clear_all()
        await self._fail()
        return False

    async def _rotate_via_refresh_token(self, x_token: SecretStr, refresh_token: SecretStr) -> None:
        """Rotate the full credential triple; persists and applies on success.

        Raises:
            LoginFailed: Rotation was rejected or returned an incomplete
                response — stored credentials are cleared.
            ResourceTemporarilyUnavailable: Transient failure — credentials
                are preserved.
        """
        try:
            new_creds = await refresh_credentials(x_token, refresh_token)
        except LoginFailed:
            self._log.warning("Session and refresh tokens are both expired")
            self._clear_all()
            raise LoginFailed("Session expired. Please re-authenticate.") from None

        new_music_token = new_creds.music_token
        new_refresh_token = new_creds.refresh_token
        if new_music_token is None or new_refresh_token is None:
            self._clear_all()
            raise LoginFailed("Credential refresh returned an incomplete response.")

        self._set(self._keys.music_token, new_music_token.get_secret())
        self._set(self._keys.x_token, new_creds.x_token.get_secret())
        self._set(self._keys.refresh_token, new_refresh_token.get_secret())
        if self._hooks.apply_credentials is not None:
            await self._hooks.apply_credentials(new_creds)
        if self._hooks.post_refresh is not None and not await self._hooks.post_refresh():
            # Stored creds are fresh, but the provider-side finalization
            # failed (e.g. cookie refresh) — surface it instead of silently
            # reporting success while the next request would 401.
            raise LoginFailed("Credential refresh succeeded but session finalization failed.")
        self._log.info("Re-issued credentials silently from refresh token")

    async def _try_rotation(self, x_token: SecretStr, refresh_token: SecretStr | None) -> bool:
        if refresh_token is None:
            return False
        try:
            await self._rotate_via_refresh_token(x_token, refresh_token)
        except LoginFailed:
            return False
        else:
            return True

    def _clear_all(self) -> None:
        self._set(self._keys.music_token, None)
        self._set(self._keys.x_token, None)
        self._set(self._keys.refresh_token, None)

    async def _fail(self) -> None:
        if self._hooks.on_failure is not None:
            await self._hooks.on_failure()
