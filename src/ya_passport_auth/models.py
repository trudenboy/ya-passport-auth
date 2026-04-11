"""Data models used across the library."""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["AccountInfo", "AuthSession", "CaptchaChallenge"]


@dataclass(frozen=True, slots=True)
class AccountInfo:
    """Non-secret account metadata from the ``short_info`` endpoint."""

    uid: int
    display_login: str | None = None
    display_name: str | None = None
    public_id: str | None = None


@dataclass(frozen=True, slots=True, repr=False)
class AuthSession:
    """Tracks multi-step auth state between login calls.

    Returned by :meth:`PassportClient.start_password_auth` and passed
    into subsequent password / SMS / magic-link / captcha methods.

    ``auth_methods`` lists the methods Yandex allows for this account
    (e.g. ``("password", "magic_x_token", "sms")``).
    """

    track_id: str
    csrf_token: str
    auth_methods: tuple[str, ...]
    magic_link_email: str | None = None

    def __repr__(self) -> str:
        return (
            f"AuthSession(track_id={self.track_id!r}, csrf_token='***', "
            f"auth_methods={self.auth_methods!r})"
        )


@dataclass(frozen=True, slots=True)
class CaptchaChallenge:
    """Captcha data returned when Yandex requires human verification.

    ``image_url`` points to the captcha image the user must solve.
    ``key`` is the opaque identifier sent back when submitting the answer.
    """

    image_url: str
    key: str
