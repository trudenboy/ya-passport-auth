"""E2E — full QR login flow with new BFF + old status endpoint."""

from __future__ import annotations

import asyncio

import aiohttp
from yarl import URL

from ya_passport_auth.config import ClientConfig
from ya_passport_auth.constants import (
    CSRF_PATTERNS,
    MUSIC_CLIENT_ID,
    MUSIC_CLIENT_SECRET,
    MUSIC_TOKEN_URL,
    PASSPORT_API_URL,
    PASSPORT_CLIENT_ID,
    PASSPORT_CLIENT_SECRET,
    PASSPORT_URL,
)

_AM_URL = f"{PASSPORT_URL}/am?app_platform=android"
_BFF = f"{PASSPORT_URL}/pwl-yandex/api/passport"
_STATUS_URL = f"{PASSPORT_URL}/auth/new/magic/status/"
_TOKEN_URL = f"{PASSPORT_API_URL}/1/bundle/oauth/token_by_sessionid"


async def main() -> None:
    config = ClientConfig()
    jar = aiohttp.CookieJar()
    async with aiohttp.ClientSession(cookie_jar=jar) as session:
        ua = config.user_agent
        hdrs = {"User-Agent": ua, "Origin": PASSPORT_URL, "Referer": f"{PASSPORT_URL}/pwl-yandex"}

        # ── Step 1: GET /am → CSRF ────────────────────────────────────
        print("=" * 50)
        print("STEP 1: GET /am → CSRF")
        r = await session.get(_AM_URL, headers={"User-Agent": ua})
        html = await r.text()
        r.release()
        csrf_am = None
        for pat in CSRF_PATTERNS:
            m = pat.search(html)
            if m and m.group(1):
                csrf_am = m.group(1)
                break
        if csrf_am is None:
            print("  [FAIL] CSRF token not found in /am page")
            return
        print(f"  csrf_am: present ({len(csrf_am)} chars)")

        # ── Step 2: multistep_start → track_id ────────────────────────
        print("\nSTEP 2: multistep_start")
        r2 = await session.post(
            f"{_BFF}/auth/multistep_start",
            data={},
            headers={**hdrs, "X-CSRF-Token": csrf_am},
        )
        d2 = await r2.json()
        r2.release()
        track_id = d2["track_id"]
        print(f"  track_id: {track_id}")
        print(f"  auth_methods: {d2.get('auth_methods')}")

        # ── Step 3: password/submit → QR session ──────────────────────
        print("\nSTEP 3: password/submit → QR session")
        r3 = await session.post(
            f"{_BFF}/auth/password/submit",
            data={
                "track_id": track_id,
                "with_code": "1",
                "retpath": "https://passport.yandex.ru/profile",
            },
            headers={**hdrs, "X-CSRF-Token": csrf_am},
        )
        d3 = await r3.json()
        r3.release()
        csrf_submit = d3["csrf_token"]
        user_code = d3.get("user_code")
        print(f"  csrf_submit: present ({len(csrf_submit)} chars)")
        print(f"  user_code: {user_code}")

        # ── Step 4: QR URL ────────────────────────────────────────────
        qr_url = f"{PASSPORT_URL}/auth/magic/code/?track_id={track_id}"
        print("\nSTEP 4: Open this URL on your phone (or any QR renderer):")
        print(f"  {qr_url}")
        print("\nWaiting for scan. Polling...")

        # ── Step 5: Poll old /auth/new/magic/status/ ──────────────────
        for i in range(150):
            await asyncio.sleep(2)
            r5 = await session.post(
                _STATUS_URL,
                data={"track_id": track_id, "csrf_token": csrf_submit},
                headers={"User-Agent": ua},
            )
            body5 = await r5.text()
            r5.release()
            if body5 != "{}":
                print(f"  Poll {i + 1}: {body5[:200]}")
            if '"status":"ok"' in body5:
                print("\n[OK] QR CONFIRMED!")
                break
        else:
            print("\nTimeout — QR not scanned")
            return

        # ── Step 6: x_token exchange ──────────────────────────────────
        print("\nSTEP 6: x_token exchange")
        filtered = session.cookie_jar.filter_cookies(URL(PASSPORT_URL))
        cookie_str = "; ".join(f"{k}={v.value}" for k, v in filtered.items())
        print(f"  Cookies: {list(filtered.keys())}")

        r6 = await session.post(
            _TOKEN_URL,
            data={
                "client_id": PASSPORT_CLIENT_ID,
                "client_secret": PASSPORT_CLIENT_SECRET,
            },
            headers={
                "User-Agent": ua,
                "Ya-Client-Host": "passport.yandex.ru",
                "Ya-Client-Cookie": cookie_str,
            },
        )
        d6 = await r6.json()
        r6.release()
        if "access_token" in d6:
            x_token = d6["access_token"]
            print(f"  x_token: present ({len(x_token)} chars)")
        else:
            print(f"  ERROR: {d6}")
            return

        # ── Step 7: Music token ───────────────────────────────────────
        print("\nSTEP 7: music_token exchange")
        r7 = await session.post(
            MUSIC_TOKEN_URL,
            data={
                "client_id": MUSIC_CLIENT_ID,
                "client_secret": MUSIC_CLIENT_SECRET,
                "grant_type": "x-token",
                "access_token": x_token,
            },
            headers={"User-Agent": ua},
        )
        d7 = await r7.json()
        r7.release()
        if "access_token" in d7:
            music_token = d7["access_token"]
            print(f"  music_token: present ({len(music_token)} chars)")
        else:
            print(f"  ERROR: {d7}")
            return

        # ── Step 8: Account info ──────────────────────────────────────
        print("\nSTEP 8: Account info")
        r8 = await session.get(
            f"{PASSPORT_API_URL}/1/bundle/account/short_info/?avatar_size=islands-300",
            headers={"User-Agent": ua, "Authorization": f"OAuth {x_token}"},
        )
        d8_text = await r8.text()
        r8.release()
        print(f"  raw response: {d8_text[:500]}")

        # ── Step 9: Session refresh ───────────────────────────────────
        print("\nSTEP 9: Passport session refresh")
        r9 = await session.post(
            f"{PASSPORT_API_URL}/1/bundle/auth/x_token/",
            data={"type": "x-token", "retpath": PASSPORT_URL},
            headers={"User-Agent": ua, "Ya-Consumer-Authorization": f"OAuth {x_token}"},
        )
        d9 = await r9.json()
        r9.release()
        print(f"  status: {d9.get('status')}")
        if d9.get("status") == "ok" and d9.get("track_id"):
            r9b = await session.get(
                f"{PASSPORT_URL}/auth/session/",
                headers={"User-Agent": ua, "track_id": d9["track_id"]},
                allow_redirects=False,
            )
            await r9b.text()
            r9b.release()
            print("  [OK] Session cookies refreshed")

        # ── Step 10: Quasar CSRF probe ────────────────────────────────
        print("\nSTEP 10: Quasar CSRF probe")
        probes = [
            ("quasar.yandex.ru/", "https://quasar.yandex.ru/"),
            ("quasar.yandex.ru/csrf_token", "https://quasar.yandex.ru/csrf_token"),
            ("quasar.yandex.ru/get_csrf_token", "https://quasar.yandex.ru/get_csrf_token"),
            ("yandex.ru/quasar/iot", "https://yandex.ru/quasar/iot"),
            ("iot-root", "https://iot.quasar.yandex.ru/"),
            ("iot/csrf_token", "https://iot.quasar.yandex.ru/csrf_token"),
            ("iot/m/v3/user/info", "https://iot.quasar.yandex.ru/m/v3/user/info"),
        ]
        for label, url in probes:
            try:
                r10 = await session.get(
                    url,
                    headers={"User-Agent": ua, "Referer": "https://yandex.ru/quasar/iot"},
                    allow_redirects=False,
                )
                status = r10.status
                hdr_keys = [k for k in r10.headers if "csrf" in k.lower()]
                csrf_headers = {k: r10.headers.get(k) for k in hdr_keys}
                body = (await r10.text())[:150]
                r10.release()
                print(f"  {label}: status={status} csrf_headers={csrf_headers} body={body!r}")
            except Exception as e:
                print(f"  {label}: EXC {e}")

        print("\n" + "=" * 50)
        print("ALL E2E STEPS COMPLETED!")
        print("=" * 50)


if __name__ == "__main__":
    asyncio.run(main())
