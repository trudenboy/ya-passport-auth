"""E2E verification of ALL ya-passport-auth flows on a real Yandex account.

Covers:
  1. QR login (scan on phone)
  2. Password login
  3. SMS verification (after password start)
  4. Magic link (email confirmation)
  5. Captcha fetch (no solve — just validates the URL is returned)
  6. Cookie login (reuses cookies from a prior flow)
  7. Token validation, account info, music token refresh
  8. Quasar CSRF + Glagol device token (if smart home is configured)

Run with:
    uv run python e2e_all_flows.py

The script is interactive — it will prompt you for which flow to test
and for credentials when needed.
"""

from __future__ import annotations

import asyncio
import getpass
import logging
import sys

from ya_passport_auth.client import PassportClient
from ya_passport_auth.config import ClientConfig
from ya_passport_auth.credentials import Credentials, SecretStr
from ya_passport_auth.exceptions import (
    AuthFailedError,
    CaptchaRequiredError,
    PasswordError,
)
from ya_passport_auth.models import AuthSession, CaptchaChallenge

logging.basicConfig(
    level=logging.DEBUG,
    format="%(levelname)-7s %(name)s: %(message)s",
)

HEADER = "=" * 60
DIVIDER = "-" * 60


# ─── Helpers ──────────────────────────────────────────────────────────────


def _banner(title: str) -> None:
    print(f"\n{HEADER}")
    print(f"  {title}")
    print(HEADER)


def _ok(msg: str) -> None:
    print(f"  \033[32m[OK]\033[0m {msg}")


def _fail(msg: str) -> None:
    print(f"  \033[31m[FAIL]\033[0m {msg}")


def _skip(msg: str) -> None:
    print(f"  \033[33m[SKIP]\033[0m {msg}")


def _info(msg: str) -> None:
    print(f"  {msg}")


def _print_creds(creds: Credentials) -> None:
    _info(f"uid           : {creds.uid}")
    _info(f"display_login : {creds.display_login}")
    _info(f"x_token       : {creds.x_token}")
    _info(f"music_token   : {creds.music_token}")
    assert isinstance(creds.x_token, SecretStr)
    assert len(creds.x_token.get_secret()) > 10
    if creds.music_token is not None:
        assert len(creds.music_token.get_secret()) > 10


def _menu(prompt: str, choices: list[str]) -> int:
    """Simple numbered menu, returns 0-based index."""
    print()
    for i, c in enumerate(choices, 1):
        print(f"  {i}) {c}")
    while True:
        try:
            n = int(input(f"\n{prompt} [1-{len(choices)}]: "))
            if 1 <= n <= len(choices):
                return n - 1
        except (ValueError, EOFError):
            pass
        print("  Invalid choice, try again.")


# ─── Flow testers ────────────────────────────────────────────────────────


async def test_qr_login(client: PassportClient) -> Credentials:
    """Flow 1: QR login — scan with Yandex app on phone."""
    _banner("FLOW 1: QR Login")

    qr = await client.start_qr_login()
    _info(f"track_id : {qr.track_id}")
    print()
    print("  Open this URL on your phone (or scan QR):")
    print(f"    \033[1m{qr.qr_url}\033[0m")
    print()
    print("  Waiting up to 300 s for confirmation...")

    creds = await client.poll_qr_until_confirmed(qr)
    _print_creds(creds)
    _ok("QR login complete")
    return creds


async def test_password_login(client: PassportClient) -> Credentials:
    """Flow 2: Password login."""
    _banner("FLOW 2: Password Login")

    username = input("  Yandex login (email/phone): ").strip()
    auth = await client.start_password_auth(username)
    _info(f"track_id     : {auth.track_id}")
    _info(f"auth_methods : {auth.auth_methods}")
    if auth.magic_link_email:
        _info(f"magic_link_email: {auth.magic_link_email}")

    password = getpass.getpass("  Password: ")
    try:
        creds = await client.login_password(auth, password)
    except CaptchaRequiredError:
        _info("Captcha required! Fetching...")
        creds = await _handle_captcha_then_password(client, auth, password)
        return creds
    except PasswordError as exc:
        _fail(f"Wrong password: {exc}")
        sys.exit(1)
    else:
        _print_creds(creds)
        _ok("Password login complete")
        return creds


async def _handle_captcha_then_password(
    client: PassportClient,
    auth: AuthSession,
    password: str,
) -> Credentials:
    """Solve CAPTCHA, then retry password."""
    challenge = await client.get_captcha(auth)
    _info(f"Captcha image URL: {challenge.image_url}")
    _info("Open the URL above in a browser and type the answer below.")
    answer = input("  Captcha answer: ").strip()
    accepted = await client.solve_captcha(auth, challenge, answer)
    if not accepted:
        _fail("Captcha rejected by server")
        sys.exit(1)
    _ok("Captcha accepted, retrying password...")
    creds = await client.login_password(auth, password)
    _print_creds(creds)
    _ok("Password + captcha login complete")
    return creds


async def test_sms_login(client: PassportClient) -> Credentials:
    """Flow 3: SMS code login (start_auth → request_sms → submit_sms)."""
    _banner("FLOW 3: SMS Login")

    username = input("  Yandex login (email/phone): ").strip()
    auth = await client.start_password_auth(username)
    _info(f"track_id     : {auth.track_id}")
    _info(f"auth_methods : {auth.auth_methods}")

    if "sms" not in " ".join(auth.auth_methods).lower():
        _skip("SMS not available for this account. Methods: " + str(auth.auth_methods))
        sys.exit(1)

    _info("Requesting SMS code...")
    await client.request_sms(auth)
    _ok("SMS sent to your phone")

    code = input("  Enter SMS code: ").strip()
    creds = await client.login_sms(auth, code)
    _print_creds(creds)
    _ok("SMS login complete")
    return creds


async def test_magic_link(client: PassportClient) -> Credentials:
    """Flow 4: Magic link (email confirmation)."""
    _banner("FLOW 4: Magic Link Login")

    username = input("  Yandex login (email/phone): ").strip()
    auth = await client.start_password_auth(username)
    _info(f"track_id     : {auth.track_id}")
    _info(f"auth_methods : {auth.auth_methods}")
    if auth.magic_link_email:
        _info(f"magic_link_email: {auth.magic_link_email}")

    _info("Sending magic link email...")
    await client.request_magic_link(auth)
    _ok("Magic link sent — check your email and click the link")
    _info("Polling for confirmation (up to 300 s)...")

    creds = await client.poll_magic_link(auth, total_timeout=300.0)
    _print_creds(creds)
    _ok("Magic link login complete")
    return creds


async def test_captcha_fetch(client: PassportClient) -> None:
    """Flow 5: Captcha — just fetch the challenge, don't solve."""
    _banner("FLOW 5: Captcha Fetch (no solve)")

    username = input("  Yandex login (email/phone): ").strip()
    auth = await client.start_password_auth(username)
    _info(f"track_id: {auth.track_id}")

    try:
        challenge = await client.get_captcha(auth)
        _info(f"captcha image_url: {challenge.image_url}")
        _info(f"captcha key      : {challenge.key}")
        assert isinstance(challenge, CaptchaChallenge)
        assert challenge.image_url.startswith("http")
        _ok("Captcha fetched successfully")
    except AuthFailedError as exc:
        _skip(f"Captcha not available (server may not require it): {exc}")


async def test_cookie_login(client: PassportClient) -> Credentials:
    """Flow 6: Cookie login — paste raw cookies from a browser."""
    _banner("FLOW 6: Cookie Login")

    print("  Paste your Yandex session cookies (Session_id=abc; sessionid2=def):")
    cookies = input("  Cookies: ").strip()
    if not cookies:
        _fail("No cookies provided")
        sys.exit(1)

    creds = await client.login_cookies(cookies)
    _print_creds(creds)
    _ok("Cookie login complete")
    return creds


# ─── Post-auth validation ────────────────────────────────────────────────


async def validate_tokens(client: PassportClient, creds: Credentials) -> None:
    """Run validation steps on the obtained credentials."""
    x_token = creds.x_token

    # Validate x_token
    _banner("VALIDATION: x_token")
    valid = await client.validate_x_token(x_token)
    assert valid is True
    _ok("x_token is valid")

    # Account info
    _banner("VALIDATION: Account Info")
    info = await client.fetch_account_info(x_token)
    _info(f"uid          : {info.uid}")
    _info(f"display_login: {info.display_login}")
    _info(f"display_name : {info.display_name}")
    _info(f"public_id    : {info.public_id}")
    assert info.uid is not None and info.uid > 0
    _ok("Account info fetched")

    # Refresh music token
    _banner("VALIDATION: Music Token Refresh")
    new_music = await client.refresh_music_token(x_token)
    assert isinstance(new_music, SecretStr)
    assert len(new_music.get_secret()) > 10
    _info(f"new music_token: {new_music}")
    _ok("Music token refreshed")

    # Refresh passport cookies
    _banner("VALIDATION: Passport Cookie Refresh")
    await client.refresh_passport_cookies(x_token)
    _ok("Session cookies refreshed")

    # Quasar CSRF
    _banner("VALIDATION: Quasar CSRF")
    try:
        quasar_csrf = await client.get_quasar_csrf_token()
        assert isinstance(quasar_csrf, SecretStr)
        _info(f"quasar csrf: {quasar_csrf}")
        _ok("Quasar CSRF token fetched")
    except Exception as exc:
        _skip(f"Quasar CSRF failed (may need smart home setup): {exc}")

    # Glagol device token
    _banner("VALIDATION: Glagol Device Token")
    try:
        device_id = input("  Station device_id (or Enter to skip): ").strip()
        platform = input("  Platform (e.g. yandexstation, default=yandexstation): ").strip()
        if not device_id:
            _skip("No device_id provided")
        else:
            glagol = await client.get_glagol_device_token(
                x_token,
                device_id=device_id,
                platform=platform or "yandexstation",
            )
            assert isinstance(glagol, SecretStr)
            _info(f"glagol token: {glagol}")
            _ok("Glagol device token fetched")
    except Exception as exc:
        _skip(f"Glagol token failed: {exc}")

    # SecretStr repr safety
    _banner("VALIDATION: SecretStr Safety")
    raw_x = x_token.get_secret()
    assert raw_x not in repr(creds)
    assert raw_x not in str(x_token)
    assert raw_x not in f"{x_token}"
    assert raw_x not in f"{x_token!r}"
    _ok("SecretStr never leaks tokens")

    # Credentials frozen
    _banner("VALIDATION: Credentials Immutability")
    try:
        creds.uid = 0  # type: ignore[misc]
        _fail("Credentials is mutable!")
    except AttributeError:
        _ok("Credentials is frozen")


# ─── Main ─────────────────────────────────────────────────────────────────


async def main() -> None:
    print(HEADER)
    print("  ya-passport-auth — E2E test for ALL flows")
    print(HEADER)

    flow_idx = _menu(
        "Select auth flow to test:",
        [
            "QR login (scan with Yandex app)",
            "Password login",
            "SMS code login",
            "Magic link (email)",
            "Captcha fetch only (no solve)",
            "Cookie login (paste browser cookies)",
            "Run ALL flows sequentially",
        ],
    )

    config = ClientConfig(
        qr_poll_interval_seconds=2.0,
        qr_poll_total_timeout_seconds=300.0,
    )

    async with PassportClient.create(config=config) as client:
        creds: Credentials | None = None

        if flow_idx == 6:  # All flows
            # QR
            try:
                creds = await test_qr_login(client)
                await validate_tokens(client, creds)
            except Exception as exc:
                _fail(f"QR login failed: {exc}")

            # Password (new client to get fresh cookies)
            async with PassportClient.create(config=config) as client2:
                try:
                    creds = await test_password_login(client2)
                    await validate_tokens(client2, creds)
                except Exception as exc:
                    _fail(f"Password login failed: {exc}")

            # SMS
            async with PassportClient.create(config=config) as client3:
                try:
                    creds = await test_sms_login(client3)
                    await validate_tokens(client3, creds)
                except Exception as exc:
                    _fail(f"SMS login failed: {exc}")

            # Magic link
            async with PassportClient.create(config=config) as client4:
                try:
                    creds = await test_magic_link(client4)
                    await validate_tokens(client4, creds)
                except Exception as exc:
                    _fail(f"Magic link login failed: {exc}")

            # Captcha
            async with PassportClient.create(config=config) as client5:
                try:
                    await test_captcha_fetch(client5)
                except Exception as exc:
                    _fail(f"Captcha fetch failed: {exc}")

            # Cookie login
            async with PassportClient.create(config=config) as client6:
                try:
                    creds = await test_cookie_login(client6)
                    await validate_tokens(client6, creds)
                except Exception as exc:
                    _fail(f"Cookie login failed: {exc}")

        else:
            flow_map = {
                0: test_qr_login,
                1: test_password_login,
                2: test_sms_login,
                3: test_magic_link,
                5: test_cookie_login,
            }

            if flow_idx == 4:
                await test_captcha_fetch(client)
            elif flow_idx in flow_map:
                creds = await flow_map[flow_idx](client)
                if creds:
                    run_validation = _menu(
                        "Run post-auth token validation?",
                        ["Yes — validate tokens, account info, Quasar, Glagol", "No — done"],
                    )
                    if run_validation == 0:
                        await validate_tokens(client, creds)

    _banner("ALL E2E TESTS COMPLETED")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted.")
        sys.exit(130)
