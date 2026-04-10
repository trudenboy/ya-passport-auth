# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
