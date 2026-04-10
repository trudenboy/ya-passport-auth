# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-04-10

### Changed

- **Breaking (internal endpoints):** QR login now targets the new Passport
  web BFF at `/pwl-yandex/api/passport/`. The flow became three steps —
  `GET /am` (CSRF scrape) → `POST /auth/multistep_start` → `POST
  /auth/password/submit` — with the page CSRF delivered via the
  `X-CSRF-Token` header instead of the form body. The legacy
  `/registration-validations/auth/password/submit` endpoint started
  returning `403` and is no longer used.
- `AccountInfoFetcher` now sends `?avatar_size=islands-300` to
  `/1/bundle/account/short_info/`. Without this query parameter the
  endpoint now responds with `{"status":"error","errors":["avatar_size.empty"]}`
  and all user fields come back empty.
- `QuasarCsrfFetcher` switched from the old
  `iot.quasar.yandex.ru/m/v3/user/devices` (`x-csrf-token` response
  header) to the dedicated `https://quasar.yandex.ru/csrf_token`
  endpoint that returns `{"status":"ok","token":"…"}`. The public
  `PassportClient.get_quasar_csrf_token()` API is unchanged.
- `ClientConfig.allowed_hosts` gained `quasar.yandex.ru`.

### Fixed

- QR `password/submit` now rejects any non-`ok` status (not just `"error"`),
  preventing misleading "missing csrf_token" errors for captcha/validation states.
- `QuasarCsrfFetcher` error messages now include the actual status value
  returned by the endpoint for easier diagnosis.
- `PASSPORT_BFF_URL` added to `constants.__all__`.

### Added

- `.github/copilot-instructions.md` with architecture, commands, security
  invariants, and conventions for Copilot context.
- E2E scripts (`e2e_test.py`, `e2e_debug.py`) for live endpoint validation.
- 201 tests, 99% branch coverage.

### Verified

- Full end-to-end flow re-validated against a real Yandex account:
  QR login, `validate_x_token`, `fetch_account_info`,
  `refresh_music_token`, `refresh_passport_cookies`,
  `get_quasar_csrf_token`, and `SecretStr`/`Credentials` invariants all
  pass against live endpoints.

## [0.1.0] - Unreleased

### Added

- `PassportClient` facade with full async API for all Yandex Passport flows.
- QR login flow: `start_qr_login()`, `poll_qr_until_confirmed()`, `complete_qr_login()`.
- Token operations: `refresh_music_token()`, `refresh_passport_cookies()`.
- Quasar CSRF: `get_quasar_csrf_token()`.
- Glagol device token: `get_glagol_device_token()`.
- Account info: `fetch_account_info()`, `validate_x_token()`.
- `SecretStr` — opaque token wrapper that redacts in repr/str/format, blocks pickling.
- `Credentials` — frozen+slotted dataclass for token bundles.
- `MemoryCredentialStore` — async-safe in-process credential store.
- `ClientConfig` — frozen configuration with validated defaults.
- `SafeHttpClient` — host allow-list, size caps, rate limiting, error wrapping.
- `AsyncMinDelayLimiter` — minimum-delay rate limiter with injectable clock.
- `RedactingFilter` + `get_logger()` — log redaction for OAuth headers and hex tokens.
- Full exception hierarchy rooted at `YaPassportError`.
- `AccountInfo` model.
- CI pipeline: ruff, mypy --strict, pytest (py3.12+3.13 x ubuntu+macos), coverage gate.
- Pre-commit hooks: ruff, mypy, gitleaks.
- Dependabot for pip + github-actions.
- SECURITY.md with threat model.
- 189 tests, 100% branch coverage.
