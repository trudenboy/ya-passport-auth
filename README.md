# ya-passport-auth

> Async Yandex Passport (mobile) authentication library for Music Assistant providers.

[![CI](https://github.com/trudenboy/ya-passport-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/trudenboy/ya-passport-auth/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/ya-passport-auth)](https://pypi.org/project/ya-passport-auth/)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## Features

- **Three login methods** — QR code scan, OAuth Device Flow (short
  code on `ya.ru/device`, plus a `refresh_token` for silent re-auth),
  and cookie-based login.
- **Full token-derivation graph** — x\_token exchange, music\_token refresh,
  Passport cookie refresh (redirect-following), Quasar CSRF, Glagol device
  token, account info.
- **Security-first** — `SecretStr` redacts tokens in repr/str/format/tracebacks
  and blocks pickling; host allow-list with HTTPS-only enforcement; CSRF
  extraction; per-request rate limiting; response size caps; log redaction via
  `RedactingFilter`.
- **Async-native** — built on `aiohttp` with `asyncio.Lock`-protected
  rate limiter and connection management.
- **Strictly typed** — `mypy --strict` clean, PEP 561 `py.typed` marker.
- **Well tested** — 221 tests, 97.8 % branch coverage.

## Installation

```
pip install ya-passport-auth
```

## Quick start

### QR login

```python
from ya_passport_auth import PassportClient

async def qr_login():
    async with PassportClient.create() as client:
        qr = await client.start_qr_login()
        print(f"Scan QR: {qr.qr_url}")
        creds = await client.poll_qr_until_confirmed(qr)

        info = await client.fetch_account_info(creds.x_token)
        print(f"Logged in as {info.display_login} (uid={info.uid})")
```

### Device flow

OAuth 2.0 Device Authorization Grant. The user opens `ya.ru/device`
on any device, enters the short `user_code`, and the library receives
an `x_token` plus a long-lived `refresh_token` for silent re-auth later.

```python
from ya_passport_auth import DeviceCodeSession, PassportClient

async def device_login():
    def on_code(session: DeviceCodeSession) -> None:
        print(f"Open {session.verification_url} and enter: {session.user_code}")

    async with PassportClient.create() as client:
        creds = await client.login_device_code(on_code=on_code)
        # creds.refresh_token is populated (only for this flow).
        # Persist creds — the access token is valid for ~1 year.
```

After the x_token expires, mint a new one without user interaction:

```python
new_creds = await client.refresh_credentials(creds)
```

Only device-flow credentials carry a `refresh_token`; QR/cookie-login
credentials have `refresh_token=None` and cannot be silently refreshed.

### Cookie login

```python
from ya_passport_auth import PassportClient

async def cookie_login():
    cookies = "Session_id=...; sessionid2=..."  # from browser
    async with PassportClient.create() as client:
        creds = await client.login_cookies(cookies)
        print(f"x_token acquired, music_token ready")
```

## Architecture

```
PassportClient  (public facade)
├── SafeHttpClient  (host allow-list, HTTPS enforcement, size caps, rate limiting)
│   └── AsyncMinDelayLimiter
└── Flows
    ├── QrLoginFlow        → CSRF scrape → session create → poll → x_token
    ├── DeviceCodeFlow     → device_code → ya.ru/device → x_token + refresh_token
    ├── CookieLoginFlow    → raw cookies → x_token
    ├── _token_exchange    → cookies→x_token, x_token→music_token  (shared)
    ├── PassportSessionRefresher  → x_token → session cookies (follows redirects)
    ├── AccountInfoFetcher → x_token → uid/login/avatar
    ├── QuasarCsrfFetcher  → CSRF token for IoT API
    └── GlagolDeviceTokenFetcher → music_token → Glagol device token
```

## API overview

### `PassportClient`

| Method | Description |
|--------|-------------|
| `start_qr_login()` | Begin QR login, returns `QrSession` |
| `poll_qr_until_confirmed(qr)` | Poll until scanned, returns `Credentials` |
| `complete_qr_login(qr)` | Exchange confirmed QR for tokens |
| `start_device_login(...)` | Begin Device Flow, returns `DeviceCodeSession` |
| `poll_device_until_confirmed(session, ...)` | Poll until confirmed, returns `Credentials` |
| `login_device_code(on_code=..., ...)` | Full Device Flow with callback |
| `refresh_credentials(creds)` | Mint fresh `Credentials` via `refresh_token` |
| `login_cookies(cookies)` | Exchange browser cookies for `Credentials` |
| `refresh_music_token(x_token)` | x\_token → music\_token |
| `refresh_passport_cookies(x_token)` | Refresh session cookies (follows redirect chain) |
| `get_quasar_csrf_token()` | Quasar CSRF token |
| `get_glagol_device_token(music_token, ...)` | Glagol device token |
| `fetch_account_info(x_token)` | Account metadata |
| `validate_x_token(x_token)` | Check if token is valid |

### `SecretStr`

Opaque wrapper — `repr()` and `str()` return `***`, pickling raises
`TypeError`. Access plaintext only via `get_secret()`.

### `Credentials`

Frozen, slotted dataclass returned by `poll_qr_until_confirmed()` and
`login_cookies()`:

| Field | Type |
|-------|------|
| `x_token` | `SecretStr` |
| `music_token` | `SecretStr \| None` |
| `uid` | `int \| None` |
| `display_login` | `str \| None` |
| `refresh_token` | `SecretStr \| None` (device flow only) |

### Exception hierarchy

```
YaPassportError
├── NetworkError
│   └── UnexpectedHostError
└── AuthFailedError
    ├── InvalidCredentialsError
    ├── CsrfExtractionError
    ├── RateLimitedError
    ├── QRPendingError
    ├── QRTimeoutError
    └── DeviceCodeTimeoutError
```

## Security

- **HTTPS-only** — `_check_host()` rejects any non-`https` URL, preventing
  protocol-downgrade attacks via redirect `Location` headers.
- **Host allow-list** — every request is validated against a frozen set of
  allowed Yandex hosts. Redirect targets are checked at each hop.
- **Token redaction** — `SecretStr` hides values in `repr`/`str`/`format`;
  `RedactingFilter` scrubs OAuth headers and hex tokens from log output.
- **No pickling** — `SecretStr` and `Credentials` block `pickle`/`copy`.
- **Response size caps** — 1 MiB for JSON, 2 MiB for HTML.
- See [SECURITY.md](SECURITY.md) for the full threat model (T1–T14).

## Used by

- [ma-provider-yandex-music](https://github.com/trudenboy/ma-provider-yandex-music) — Music Assistant provider for Yandex Music
- [ma-provider-yandex-ynison](https://github.com/trudenboy/ma-provider-yandex-ynison) — Music Assistant provider for Yandex Ynison (Spotify Connect analog)
- [ma-provider-yandex-station](https://github.com/trudenboy/ma-provider-yandex-station) — Music Assistant provider for Yandex Station

## Security disclaimer

This library interacts with Yandex Passport using **public mobile OAuth client
IDs and secrets** extracted from official Yandex Android applications. These
values are well-known and present in many open-source projects; they are
treated here as constants, not secrets. Do not use this library for anything
other than authenticating into your own Yandex account.

There is no official Yandex API for the mobile Passport flow. Endpoints,
response shapes, and regex patterns may break without notice.

## License

MIT. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for third-party attribution.
