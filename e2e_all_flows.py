"""E2E verification of ya-passport-auth flows on a real Yandex account.

Covers:
  1. QR login (scan on phone)
  2. Cookie login (reuses cookies from a prior flow)
  3. Token validation, account info, music token refresh
  4. Quasar CSRF + Glagol device token (if smart home is configured)

Run with:
    uv run python e2e_all_flows.py

The script is interactive — it will prompt you for which flow to test
and for credentials when needed.
"""

from __future__ import annotations

import asyncio
import logging
import sys

from ya_passport_auth.client import PassportClient
from ya_passport_auth.config import ClientConfig
from ya_passport_auth.credentials import Credentials, SecretStr

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
    assert isinstance(creds.x_token, SecretStr)
    _info("x_token       : [SecretStr present]")
    if creds.music_token is not None:
        assert isinstance(creds.music_token, SecretStr)
        _info("music_token   : [SecretStr present]")
    else:
        _info("music_token   : None")


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


async def test_cookie_login(client: PassportClient) -> Credentials:
    """Flow 2: Cookie login — paste raw cookies from a browser."""
    _banner("FLOW 2: Cookie Login")

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
    _info("new music_token: [SecretStr present]")
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
        _info("quasar csrf: [SecretStr present]")
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
            _info("glagol token: [SecretStr present]")
            _ok("Glagol device token fetched")
    except Exception as exc:
        _skip(f"Glagol token failed: {exc}")

    # SecretStr repr safety — verify redaction without extracting secrets
    _banner("VALIDATION: SecretStr Safety")
    assert "***" in repr(creds)
    assert str(x_token) == "***"
    assert f"{x_token}" == "***"
    assert f"{x_token!r}" == "SecretStr('***')"
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
    print("  ya-passport-auth — E2E test for auth flows")
    print(HEADER)

    flow_idx = _menu(
        "Select auth flow to test:",
        [
            "QR login (scan with Yandex app)",
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

        if flow_idx == 2:  # All flows
            # QR
            try:
                creds = await test_qr_login(client)
                await validate_tokens(client, creds)
            except Exception as exc:
                _fail(f"QR login failed: {exc}")

            # Cookie login
            async with PassportClient.create(config=config) as client2:
                try:
                    creds = await test_cookie_login(client2)
                    await validate_tokens(client2, creds)
                except Exception as exc:
                    _fail(f"Cookie login failed: {exc}")

        else:
            flow_map: dict[int, object] = {
                0: test_qr_login,
                1: test_cookie_login,
            }

            handler = flow_map[flow_idx]
            creds = await handler(client)  # type: ignore[operator]
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
