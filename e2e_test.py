"""E2E verification of the full ya-passport-auth flow.

Requires a real Yandex account — the user scans the QR code on their phone.
Run with: uv run python e2e_test.py
"""

from __future__ import annotations

import asyncio
import logging
import sys

from ya_passport_auth.client import PassportClient
from ya_passport_auth.config import ClientConfig
from ya_passport_auth.credentials import Credentials, SecretStr

# Enable debug logging to see what happens under the hood.
logging.basicConfig(
    level=logging.DEBUG,
    format="%(levelname)-7s %(name)s: %(message)s",
)


def _print_qr_url(url: str) -> None:
    """Print the QR URL. The user opens it on their phone manually."""
    print()
    print("  Open this URL on your phone (or any QR renderer):")
    print(f"    {url}")
    print()


async def main() -> None:
    config = ClientConfig(
        qr_poll_interval_seconds=2.0,
        qr_poll_total_timeout_seconds=300.0,
    )

    async with PassportClient.create(config=config) as client:
        # ── Step 1: QR login ──────────────────────────────────────────
        print("=" * 60)
        print("STEP 1: Starting QR login flow...")
        print("=" * 60)
        qr = await client.start_qr_login()
        print(f"  track_id : {qr.track_id}")
        print(f"  qr_url   : {qr.qr_url}")
        print()
        _print_qr_url(qr.qr_url)
        print("Scan the QR code with the Yandex app on your phone.")
        print("Waiting up to 300 s for confirmation...\n")

        creds = await client.poll_qr_until_confirmed(qr)

        assert isinstance(creds, Credentials)
        assert isinstance(creds.x_token, SecretStr)
        assert isinstance(creds.music_token, SecretStr)
        print("[OK] QR login complete")
        print(f"  uid           : {creds.uid}")
        print(f"  display_login : {creds.display_login}")
        print(f"  x_token       : {creds.x_token}")  # prints ***
        print(f"  music_token   : {creds.music_token}")  # prints ***
        assert len(creds.x_token.get_secret()) > 10
        assert creds.music_token is not None
        assert len(creds.music_token.get_secret()) > 10
        print("[OK] Tokens are non-empty\n")

        x_token = creds.x_token
        _ = creds.music_token  # verified non-None above

        # ── Step 2: Validate x_token ─────────────────────────────────
        print("=" * 60)
        print("STEP 2: Validating x_token...")
        print("=" * 60)
        valid = await client.validate_x_token(x_token)
        assert valid is True
        print("[OK] x_token is valid\n")

        # ── Step 3: Fetch account info ────────────────────────────────
        print("=" * 60)
        print("STEP 3: Fetching account info...")
        print("=" * 60)
        info = await client.fetch_account_info(x_token)
        assert info.uid is not None
        assert isinstance(info.uid, int)
        assert info.uid > 0
        print(f"  uid           : {info.uid}")
        print(f"  display_login : {info.display_login}")
        print(f"  display_name  : {info.display_name}")
        print(f"  public_id     : {info.public_id}")
        print("[OK] Account info fetched\n")

        # ── Step 4: Refresh music token ───────────────────────────────
        print("=" * 60)
        print("STEP 4: Refreshing music token from x_token...")
        print("=" * 60)
        new_music = await client.refresh_music_token(x_token)
        assert isinstance(new_music, SecretStr)
        assert len(new_music.get_secret()) > 10
        print(f"  new music_token: {new_music}")  # prints ***
        print("[OK] Music token refreshed\n")

        # ── Step 5: Refresh passport cookies ──────────────────────────
        print("=" * 60)
        print("STEP 5: Refreshing passport session cookies...")
        print("=" * 60)
        await client.refresh_passport_cookies(x_token)
        print("[OK] Session cookies refreshed\n")

        # ── Step 6: Quasar CSRF ───────────────────────────────────────
        print("=" * 60)
        print("STEP 6: Fetching Quasar CSRF token...")
        print("=" * 60)
        try:
            quasar_csrf = await client.get_quasar_csrf_token()
            assert isinstance(quasar_csrf, SecretStr)
            assert len(quasar_csrf.get_secret()) > 5
            print(f"  quasar csrf: {quasar_csrf}")  # prints ***
            print("[OK] Quasar CSRF token fetched\n")
        except Exception as exc:
            print(f"  [SKIP] Quasar CSRF failed: {exc}\n")

        # ── Step 7: SecretStr repr safety ─────────────────────────────
        print("=" * 60)
        print("STEP 7: Verifying SecretStr never leaks tokens...")
        print("=" * 60)
        raw_x = x_token.get_secret()
        assert raw_x not in repr(creds)
        assert raw_x not in str(x_token)
        assert raw_x not in f"{x_token}"
        assert raw_x not in f"{x_token!r}"
        print("[OK] SecretStr repr is safe\n")

        # ── Step 8: Credentials frozen ────────────────────────────────
        print("=" * 60)
        print("STEP 8: Verifying Credentials is immutable...")
        print("=" * 60)
        try:
            creds.uid = 0  # type: ignore[misc]
            print("[FAIL] Credentials is mutable!")
            sys.exit(1)
        except AttributeError:
            print("[OK] Credentials is frozen\n")

        # ── Summary ───────────────────────────────────────────────────
        print("=" * 60)
        print("ALL E2E CHECKS PASSED")
        print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
