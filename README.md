# ya-passport-auth

> Async Yandex Passport (mobile) authentication library for Music Assistant providers.

[![CI](https://github.com/trudenboy/ya-passport-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/trudenboy/ya-passport-auth/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/ya-passport-auth)](https://pypi.org/project/ya-passport-auth/)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## Features

- **Full token-derivation graph** — QR login, x_token exchange, music_token
  refresh, Passport cookie refresh, Quasar CSRF, Glagol device token,
  account info.
- **Security-first** — `SecretStr` redacts tokens in repr/str/format/tracebacks,
  blocks pickling, host allow-list, CSRF extraction, rate limiting,
  response size caps, log redaction.
- **Async-native** — built on `aiohttp` with `asyncio.Lock`-protected
  rate limiter and connection management.
- **Strictly typed** — `mypy --strict` clean, PEP 561 `py.typed` marker.

## Installation

```
pip install ya-passport-auth
```

## Quick start

```python
from ya_passport_auth import PassportClient, SecretStr

async def main():
    async with PassportClient.create() as client:
        # QR login
        qr = await client.start_qr_login()
        print(f"Scan QR: {qr.qr_url}")
        creds = await client.poll_qr_until_confirmed(qr)

        # Token refresh
        new_music = await client.refresh_music_token(creds.x_token)

        # Account info
        info = await client.fetch_account_info(creds.x_token)
        print(f"Logged in as {info.display_login} (uid={info.uid})")
```

## API overview

### `PassportClient`

| Method | Description |
|--------|-------------|
| `start_qr_login()` | Begin QR login, returns `QrSession` |
| `poll_qr_until_confirmed(qr)` | Poll until scanned, returns `Credentials` |
| `complete_qr_login(qr)` | Exchange confirmed QR for tokens |
| `refresh_music_token(x_token)` | x_token -> music_token |
| `refresh_passport_cookies(x_token)` | Refresh session cookies |
| `get_quasar_csrf_token()` | Quasar CSRF token |
| `get_glagol_device_token(music_token, ...)` | Glagol device token |
| `fetch_account_info(x_token)` | Account metadata |
| `validate_x_token(x_token)` | Check if token is valid |

### `SecretStr`

Opaque wrapper — `repr()` and `str()` return `***`, pickling raises
`TypeError`. Access plaintext only via `get_secret()`.

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
    └── QRTimeoutError
```

## Security disclaimer

This library interacts with Yandex Passport using **public mobile OAuth client
IDs and secrets** extracted from official Yandex Android applications. These
values are well-known and present in many open-source projects; they are
treated here as constants, not secrets. Do not use this library for anything
other than authenticating into your own Yandex account.

There is no official Yandex API for the mobile Passport flow. Endpoints,
response shapes, and regex patterns may break without notice.

## License

MIT. See `LICENSE` and `NOTICE` for third-party attribution.
