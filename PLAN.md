# Plan: ya-passport-auth standalone library

## Context

The Music Assistant ecosystem needs four Yandex providers (**music**, **ynison**,
**smarthome**/quasar, **station**/glagol). All four derive their tokens from the
same mobile Yandex Passport OAuth flow. Today that flow lives in
`/Users/renso/Projects/ma-provider-yandex-music/provider/yandex_auth.py` — ~270 LOC
of pure aiohttp code that implements only the QR sub-flow and depends on MA
internals (`LoginFailed`, `AuthenticationHelper`). Copy-pasting it into each
provider would triple the attack surface and make security fixes impossible to
propagate.

**Goal:** extract that code into a standalone, security-first, strictly typed,
TDD-built Python library published to PyPI, re-licensed under MIT (consumer is
MIT already, AlexxIT/YandexStation upstream is also MIT so attribution is
sufficient). The library covers the full token-derivation graph needed by all
four providers in a single v0.1.0 release.

**Outcome:** `pip install ya-passport-auth` gives consumers a single async
`PassportClient` facade with methods for every Yandex token the providers need,
zero leakage of secrets in logs or repr, and a CI pipeline that gates every
change against SAST, dependency audit, license check, secrets scan, CodeQL,
SBOM, Sigstore-signed builds, and OIDC-published releases to PyPI.

---

## Repository location and release scope

- **New repo:** `/Users/renso/Projects/ya-passport-auth` (fresh `git init`)
- **PyPI name:** `ya-passport-auth`
- **Import name:** `ya_passport_auth`
- **License:** MIT (with `NOTICE` attributing AlexxIT/YandexStation MIT)
- **Python:** `>=3.12`, matrix tests on 3.12 + 3.13
- **Release scope for 0.1.0:** full API — QR login, music-token refresh,
  Passport cookie refresh, Quasar CSRF, Glagol device token, account short_info
- **TLS SPKI pinning:** opt-in via `ClientConfig.pinned_fingerprints`
  (default `None`), exposed in v1 public API
- **Docs:** README + SECURITY.md only (no mkdocs in v1)

---

## Final directory tree

```
ya-passport-auth/
├── .github/
│   ├── CODEOWNERS
│   ├── dependabot.yml
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.yml
│   │   └── security_report.md
│   └── workflows/
│       ├── ci.yml              # lint/type/test/SAST/audit/secrets/license/SBOM
│       ├── codeql.yml          # CodeQL security-extended queries
│       ├── scorecard.yml       # OpenSSF Scorecard weekly
│       ├── secrets-nightly.yml # full-history gitleaks + trufflehog
│       └── release.yml         # build + sign + SLSA + OIDC publish
├── .gitignore
├── .gitattributes
├── .pre-commit-config.yaml
├── .editorconfig
├── CHANGELOG.md                # Keep a Changelog format
├── CONTRIBUTING.md
├── LICENSE                     # MIT
├── NOTICE                      # AlexxIT attribution
├── THIRD_PARTY.md              # upstream references, commit hashes
├── README.md                   # with SECURITY DISCLAIMER
├── SECURITY.md                 # disclosure policy, threat model summary
├── pyproject.toml              # hatchling + hatch-vcs
├── uv.lock                     # committed, hash-pinned
├── src/
│   └── ya_passport_auth/
│       ├── __init__.py         # public API re-exports + __version__
│       ├── py.typed            # PEP 561 marker
│       ├── _version.py         # hatch-vcs writes at build time
│       ├── client.py           # PassportClient facade
│       ├── credentials.py      # SecretStr, Credentials, MemoryCredentialStore
│       ├── config.py           # ClientConfig (frozen dataclass)
│       ├── exceptions.py       # YaPassportError hierarchy
│       ├── http.py             # SafeHttpClient (host pinning, rate-limit, retry)
│       ├── logging.py          # get_logger + RedactingFilter
│       ├── rate_limit.py       # AsyncMinDelayLimiter
│       ├── constants.py        # endpoints, mobile client IDs, UA, regex
│       ├── models.py           # internal TypedDicts + AccountInfo
│       └── flows/
│           ├── __init__.py
│           ├── qr.py           # QrSession + QrLoginFlow
│           ├── tokens.py       # MusicTokenExchange, XTokenValidator
│           ├── session.py      # PassportSessionRefresher (login_token)
│           ├── quasar.py       # QuasarCsrfFetcher, StorageProbe
│           ├── glagol.py       # GlagolDeviceTokenFetcher
│           └── account.py      # AccountInfoFetcher (short_info)
├── tests/
│   ├── __init__.py
│   ├── conftest.py             # aioresponses, fake clock, log capture, fixture sanitizer
│   ├── fixtures/               # sanitized HTML/JSON captures, tokens = "test-token-*"
│   ├── unit/                   # primitives (credentials, rate_limit, config, http, logging)
│   ├── flows/                  # per-flow tests
│   └── integration/            # PassportClient facade end-to-end with mocked transport
└── scripts/
    └── manual_qr.py            # developer-only real-Yandex smoke test, documented in README
```

---

## Public API (`ya_passport_auth/__init__.py`)

```python
from ya_passport_auth.client import PassportClient
from ya_passport_auth.config import ClientConfig
from ya_passport_auth.credentials import (
    Credentials, SecretStr, MemoryCredentialStore,
)
from ya_passport_auth.exceptions import (
    YaPassportError,
    NetworkError, UnexpectedHostError,
    AuthFailedError, InvalidCredentialsError,
    CsrfExtractionError, RateLimitedError,
    QRPendingError, QRTimeoutError,
)
from ya_passport_auth.flows.qr import QrSession
from ya_passport_auth.models import AccountInfo
from ya_passport_auth._version import __version__
```

### `PassportClient` facade

```python
class PassportClient:
    def __init__(
        self,
        *,
        session: aiohttp.ClientSession | None = None,
        config: ClientConfig | None = None,
    ) -> None: ...

    @classmethod
    @asynccontextmanager
    async def create(
        cls, config: ClientConfig | None = None,
    ) -> AsyncIterator["PassportClient"]:
        """Owns an internal ClientSession with dedicated CookieJar,
        mobile UA, TLS verify, safe timeouts."""

    # QR login
    async def start_qr_login(self) -> QrSession: ...
    async def poll_qr_until_confirmed(
        self, qr: QrSession, *,
        poll_interval: float | None = None,
        total_timeout: float | None = None,
    ) -> Credentials: ...
    async def complete_qr_login(self, qr: QrSession) -> Credentials: ...

    # Token ops
    async def refresh_music_token(self, x_token: SecretStr) -> SecretStr: ...
    async def refresh_passport_cookies(self, x_token: SecretStr) -> None: ...
    async def get_quasar_csrf_token(self) -> SecretStr: ...
    async def get_glagol_device_token(
        self, music_token: SecretStr, *, device_id: str, platform: str,
    ) -> SecretStr: ...
    async def fetch_account_info(self, x_token: SecretStr) -> AccountInfo: ...
    async def validate_x_token(self, x_token: SecretStr) -> bool: ...

    async def close(self) -> None: ...
    async def __aenter__(self) -> "PassportClient": ...
    async def __aexit__(self, *exc: object) -> None: ...
```

### `SecretStr` and `Credentials`

- `SecretStr.__repr__` / `__str__` → `"***"`, `get_secret()` returns plain
- `__reduce__` raises `TypeError` → unpickleable → no accidental leak via
  multiprocessing, Redis, disk cache
- `__slots__`, frozen where applicable
- `Credentials` holds `x_token`, `music_token | None`, `uid | None`,
  `display_login | None`; repr never contains token substrings
- `MemoryCredentialStore` is the **only** shipped store; persistence is the
  caller's responsibility (MA's config `encrypted=True`)

### `ClientConfig` (frozen dataclass)

```python
user_agent: str = DEFAULT_MOBILE_UA
total_timeout_seconds: float = 30.0
connect_timeout_seconds: float = 10.0
min_request_interval_seconds: float = 0.2
max_retries: int = 2
qr_poll_interval_seconds: float = 2.0
qr_poll_total_timeout_seconds: float = 120.0
allowed_hosts: frozenset[str] = frozenset({
    "passport.yandex.ru",
    "mobileproxy.passport.yandex.net",
    "oauth.mobile.yandex.net",
    "oauth.yandex.ru",
    "yandex.ru",
    "quasar.yandex.net",
    "iot.quasar.yandex.ru",
})
pinned_fingerprints: frozenset[str] | None = None  # opt-in SPKI SHA256
# verify_tls is always True; no public path to disable
```

### Exceptions hierarchy

```
YaPassportError
├── NetworkError
│   └── UnexpectedHostError
└── AuthFailedError
    ├── InvalidCredentialsError
    ├── CsrfExtractionError
    ├── RateLimitedError        # HTTP 429
    ├── QRPendingError          # QR not yet scanned (control flow)
    └── QRTimeoutError          # poll loop expired
```

All exceptions carry `status_code: int | None` and `endpoint: str | None`.
Never accept `SecretStr` or `Credentials` in messages.

---

## Security threat model

### Mitigated threats

| # | Threat | Mitigation |
|---|---|---|
| T1 | Token leak via logs/tracebacks | `SecretStr` redacts repr/str; `RedactingFilter` scrubs `OAuth \S+` and 32+ hex runs; only endpoint paths + status codes logged |
| T2 | Token leak via pickling/serialization | `SecretStr.__reduce__` raises `TypeError`; transitively applies to `Credentials` |
| T3 | TLS downgrade/MITM | `verify_tls=True` fixed, no public toggle; opt-in SPKI pinning via `ClientConfig.pinned_fingerprints` |
| T4 | SSRF via open redirect | `allow_redirects=False` on all requests; manual `response.host in allowed_hosts` check; raises `UnexpectedHostError` |
| T5 | DoS via unbounded response body | 1 MiB cap on JSON bodies, 2 MiB on HTML (CSRF pages) |
| T6 | ReDoS on CSRF regex | Anchored, non-greedy, explicit character classes; fuzzed via hypothesis |
| T7 | Rate-limit ban by Yandex | `AsyncMinDelayLimiter` 0.2s; 429 → `RateLimitedError` without retry; 403 → single retry after CSRF refetch; max 2 retries total |
| T8 | Cookie leakage between callers | Dedicated `CookieJar` per `PassportClient`; cleared on `close()`; never returned via public API |
| T9 | Supply-chain compromise | `uv.lock` hash-pinned, `--require-hashes` in CI, Dependabot, pip-audit, osv-scanner, Sigstore wheels, SLSA v1.0 provenance, OIDC-only PyPI publish |
| T10 | Secrets committed to repo | pre-commit + CI gitleaks + nightly full-history scan + trufflehog + `detect-private-key` |
| T11 | Typo-squatted dependency | Minimum version pins + hashed lockfile + `dependency-review-action` |
| T12 | Log injection via attacker-controlled strings | `%s` placeholder logging only; CRLF stripped by filter |
| T13 | Credential exposure via `vars()` / `__dict__` | `slots=True, frozen=True` on `Credentials`; `SecretStr` slotted with no public attrs |
| T14 | Test fixtures leaking real tokens | Fixtures sanitized, tokens match `test-token-[a-z0-9]+`; autouse conftest scanner fails the run if a real-looking 32-hex token is found |

### Explicitly out of scope

- Host compromise / memory scraping (SecretStr is not an enclave)
- Side-channel timing attacks on token comparison (no attacker-controlled equality)
- Encrypted at-rest storage (caller's responsibility)
- CAPTCHA / anti-bot bypass
- Reverse engineering of Yandex mobile client secrets (already public; treated as
  well-known constants with README disclaimer)

---

## `pyproject.toml` key sections

```toml
[build-system]
requires = ["hatchling>=1.25", "hatch-vcs>=0.4"]
build-backend = "hatchling.build"

[project]
name = "ya-passport-auth"
dynamic = ["version"]
description = "Async Yandex Passport (mobile) auth library for Music Assistant providers"
readme = "README.md"
license = { file = "LICENSE" }
requires-python = ">=3.12"
dependencies = [
    "aiohttp>=3.10,<4",
    "yarl>=1.12",
]

[project.optional-dependencies]
dev = [
    "pytest>=8", "pytest-asyncio>=0.23", "pytest-cov>=5",
    "aioresponses>=0.7.6", "hypothesis>=6",
    "mypy>=1.11", "ruff>=0.6",
    "bandit[toml]>=1.7", "pip-audit>=2.7",
    "cyclonedx-bom>=4", "liccheck>=0.9",
    "pre-commit>=3.8",
]

[tool.hatch.version]
source = "vcs"

[tool.hatch.build.targets.wheel]
packages = ["src/ya_passport_auth"]

[tool.mypy]
strict = true
python_version = "3.12"
files = ["src", "tests"]
disallow_any_explicit = true
warn_unreachable = true
enable_error_code = ["redundant-expr", "truthy-bool", "ignore-without-code"]

[tool.ruff]
line-length = 100
target-version = "py312"
src = ["src", "tests"]

[tool.ruff.lint]
select = ["E","F","W","I","N","UP","B","A","C4","DTZ","T20","SIM","S","ASYNC","RUF","PL","TRY","PERF"]

[tool.ruff.lint.per-file-ignores]
"tests/**" = ["S101","S105","S106","PLR2004"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
addopts = "-ra --strict-markers --strict-config --cov=ya_passport_auth --cov-report=term-missing --cov-report=xml --cov-fail-under=95"
testpaths = ["tests"]

[tool.coverage.run]
branch = true
source = ["ya_passport_auth"]

[tool.bandit]
exclude_dirs = ["tests"]
```

---

## CI pipeline

All third-party actions pinned by **commit SHA**, not tag. Each job declares
minimum `permissions:`; repo default is `permissions: {}`.

### `.github/workflows/ci.yml` (PR + main push)

Parallel jobs, matrix on `python-version: [3.12, 3.13]` and `os: [ubuntu, macos]` for tests:

1. **lint** — `ruff check .`, `ruff format --check .`
2. **typecheck** — `mypy --strict src tests`
3. **test** — `pytest`, coverage gate `--cov-fail-under=95`, uploads `coverage.xml`
4. **bandit** — `-ll` (HIGH severity fails)
5. **semgrep** — rulesets `p/python`, `p/security-audit`, `p/owasp-top-ten`, fails on ERROR
6. **pip-audit** — `pypa/gh-action-pip-audit`
7. **osv-scanner** — `google/osv-scanner-action` reading `uv.lock`
8. **gitleaks** — PR-diff scan
9. **dependency-review** — `actions/dependency-review-action`, fail-on-severity: moderate
10. **license-check** — `liccheck` allowing MIT/BSD/Apache-2.0/ISC/PSF only
11. **sbom** — `cyclonedx-py`, uploaded as artifact

### `.github/workflows/codeql.yml`
CodeQL Python with default + `security-extended` queries.

### `.github/workflows/scorecard.yml`
`ossf/scorecard-action` weekly cron + on main push, publishes results to badge.

### `.github/workflows/secrets-nightly.yml`
Nightly full-history scan: `gitleaks detect --log-opts="--all"` + `trufflehog git file://.`

### `.github/workflows/release.yml` (tag `v*`)

1. **build** — `pypa/build`, emits `dist/*`
2. **sign** — `sigstore/gh-action-sigstore-python` signs every wheel + sdist
3. **provenance** — `slsa-framework/slsa-github-generator` emits SLSA v1.0
4. **publish-testpypi** — OIDC trusted publisher, runs on `v*-rc*` tags
5. **publish-pypi** — OIDC trusted publisher, requires manual environment approval,
   runs only on final tags
6. **github-release** — attaches wheels + sigstore bundles + SBOM

### `.github/dependabot.yml`
Weekly for `pip` + `github-actions` ecosystems.

### Branch protection (documented in CONTRIBUTING.md)
Require all of: lint, typecheck, test (3.12), test (3.13), bandit, semgrep,
pip-audit, osv-scanner, gitleaks, dependency-review, license-check, codeql.
Require signed commits, linear history, CODEOWNERS review, no force pushes.

### `.pre-commit-config.yaml`
`ruff check --fix` + `ruff format`; `mypy --strict` (src only for speed);
`gitleaks`; `check-added-large-files` (200 KB); `detect-private-key`;
`check-merge-conflict`; `end-of-file-fixer`; `trailing-whitespace`.

---

## TDD task sequence

Strict red-green-refactor. No implementation file is created until its test is
red. Fixtures in `tests/fixtures/` are the only HTML/JSON source — **no live
network in CI**. Manual fixture capture lives in `scripts/capture_fixtures.py`.

### Phase 0 — scaffolding
1. `git init`, `.gitignore`, `LICENSE`, `NOTICE`, empty `pyproject.toml`, empty
   `src/ya_passport_auth/__init__.py`, `py.typed`.
2. Wire `uv`, ruff, mypy, pytest. Add `tests/unit/test_import.py::test_version_importable`.
3. Stand up `ci.yml` (lint + typecheck + test only). Must go green.
4. Add `pre-commit` config and run once.

### Phase 1 — primitives
5. **RED/GREEN** `test_secretstr.py` → `credentials.SecretStr`
6. **RED/GREEN** `test_credentials.py` → `Credentials`, `MemoryCredentialStore`
7. **RED/GREEN** `test_exceptions.py` → exception hierarchy
8. **RED/GREEN** `test_config.py` → `ClientConfig` (frozen, allowed_hosts, pinned_fingerprints=None)
9. **RED/GREEN** `test_rate_limit.py` → `AsyncMinDelayLimiter` (fake monotonic clock)
10. **RED/GREEN** `test_logging_redaction.py` → `RedactingFilter`, `get_logger`

### Phase 2 — SafeHttpClient
11. `test_http_safe_client.py::test_allowed_host_passes` (aioresponses)
12. `test_disallowed_host_raises_unexpected_host_error`
13. `test_http_non_json_response_raises`
14. `test_http_429_raises_rate_limited_no_retry`
15. `test_http_network_error_wrapped`
16. `test_http_response_size_cap` (2 MiB HTML, 1 MiB JSON)
17. `test_http_enforces_rate_limit`
18. **GREEN** implement `http.SafeHttpClient`

### Phase 3 — QR login flow
19–24. **RED** CSRF extraction (3 patterns + fail path), submit status/missing track_id
25. **GREEN** `flows/qr.py::QrLoginFlow.get_qr`
26. **RED/GREEN** `check_status` (pending/ok)
27. **RED/GREEN** `get_x_token` (no cookies → `InvalidCredentialsError`; success)
28. **RED/GREEN** `MusicTokenExchange.exchange`
29. **RED/GREEN** `PassportClient.poll_qr_until_confirmed` timeout (fake clock)
30. **RED/GREEN** `PassportClient.complete_qr_login` returns full `Credentials`
31. **GREEN** `PassportClient.start_qr_login` + facade wiring

### Phase 4 — remaining flows
32. `flows/account.py::AccountInfoFetcher` — short_info (200/401/403/missing fields)
33. `flows/tokens.py::XTokenValidator` — delegate to short_info
34. `flows/session.py::PassportSessionRefresher` — two-step `bundle/auth/x_token/` + session cookie endpoint
35. `flows/quasar.py::QuasarStorageProbe` + `QuasarCsrfFetcher` — probe + `csrfToken2` regex
36. `flows/glagol.py::GlagolDeviceTokenFetcher` — GET with `Authorization: OAuth <music_token>`

### Phase 5 — hardening & observability
37. `hypothesis` fuzz of CSRF patterns against long random input, asserts time bound
38. `test_no_tokens_in_logs` integration test across full QR flow
39. `test_credentials_not_pickleable` regression (T2)
40. Tighten coverage contexts; assert critical auth paths at 100% via coverage contexts

### Phase 6 — release prep
41. `README.md` with security disclaimer, usage snippets, CI badges
42. `SECURITY.md` with disclosure policy + threat model summary
43. `CHANGELOG.md` 0.1.0 entry
44. `release.yml` dry-run on `v0.1.0-rc1` → TestPyPI → verify OIDC flow
45. Cut `v0.1.0` tag → PyPI publish with Sigstore + SLSA

---

## Critical files

**To be created in `/Users/renso/Projects/ya-passport-auth`:**
- `src/ya_passport_auth/client.py` — `PassportClient` facade
- `src/ya_passport_auth/http.py` — `SafeHttpClient` (rate-limit, host pinning, retry, size caps)
- `src/ya_passport_auth/credentials.py` — `SecretStr`, `Credentials`
- `src/ya_passport_auth/flows/qr.py` — QR login steps
- `src/ya_passport_auth/flows/session.py` — `login_token` cookie refresh
- `src/ya_passport_auth/flows/quasar.py` — Quasar CSRF + storage probe
- `src/ya_passport_auth/flows/glagol.py` — Glagol device token
- `src/ya_passport_auth/flows/account.py` — `short_info`
- `src/ya_passport_auth/exceptions.py` — hierarchy
- `src/ya_passport_auth/config.py` — `ClientConfig`
- `src/ya_passport_auth/logging.py` — `RedactingFilter`
- `src/ya_passport_auth/rate_limit.py` — `AsyncMinDelayLimiter`
- `src/ya_passport_auth/constants.py` — endpoints, mobile client IDs, UA, regex
- `pyproject.toml`, `uv.lock`, `LICENSE`, `NOTICE`, `README.md`, `SECURITY.md`, `CHANGELOG.md`
- `.github/workflows/{ci,codeql,scorecard,secrets-nightly,release}.yml`
- `.github/dependabot.yml`, `.pre-commit-config.yaml`

**Read-only references (code & patterns to port):**
- `/Users/renso/Projects/ma-provider-yandex-music/provider/yandex_auth.py` —
  current QR implementation, endpoints, client IDs, regex patterns, error mapping
- `/Users/renso/Projects/ma-provider-yandex-music/provider/constants.py` —
  `CONF_TOKEN`, `CONF_X_TOKEN` for consumer migration reference
- `/Users/renso/Projects/ma-provider-yandex-music/provider/provider.py:159-208` —
  startup refresh pattern the library must enable
- AlexxIT/YandexStation (MIT) `yandex_session.py` — reference for `login_token`,
  `refresh_cookies`, listener pattern (concepts only; ported by spec, not by
  verbatim copy, but MIT allows verbatim copy too with attribution)

---

## Consumer migration (informational, out of scope for this repo)

In `ma-provider-yandex-music` (and later sister providers):

1. Add `ya-passport-auth>=0.1,<0.2` to `pyproject.toml`.
2. Delete `provider/yandex_auth.py`; replace `perform_qr_auth` with thin MA glue:
   ```python
   async with PassportClient.create() as client:
       qr = await client.start_qr_login()
       async with AuthenticationHelper(mass, session_id) as helper:
           helper.send_url(qr.qr_url)
           creds = await client.poll_qr_until_confirmed(qr)
       return creds.x_token.get_secret(), creds.music_token.get_secret()
   ```
3. Replace `refresh_music_token` with:
   ```python
   async with PassportClient.create() as client:
       return (await client.refresh_music_token(SecretStr(x_token))).get_secret()
   ```
4. Map `YaPassportError` subclasses to `music_assistant_models.errors.LoginFailed`
   at the provider boundary — the library does not depend on MA.

---

## Verification

### Local (developer)
1. `uv sync --frozen --all-extras`
2. `uv run pre-commit install`
3. `uv run pytest` — must pass with ≥95% coverage
4. `uv run mypy --strict src tests` — zero errors
5. `uv run ruff check . && uv run ruff format --check .`
6. `uv run bandit -c pyproject.toml -r src -ll`
7. `uv run pip-audit`
8. `uv build` → `dist/ya_passport_auth-<ver>-py3-none-any.whl` + sdist
9. Smoke install: `uv run --with ./dist/ya_passport_auth-*.whl python -c "import ya_passport_auth; print(ya_passport_auth.__version__)"`
10. Manual QR test (never in CI): `uv run python scripts/manual_qr.py` — prints
    QR URL, polls, prints `SecretStr` reprs only (never raw tokens), verifies
    `short_info` login matches the test account, writes nothing to disk

### CI
- All jobs in `ci.yml`, `codeql.yml`, `scorecard.yml`, `secrets-nightly.yml` green
- Coverage `coverage.xml` uploaded, badge wired in README
- SBOM artifact downloadable from workflow run
- Release dry-run on `v0.1.0-rc1` tag publishes to TestPyPI with signed artifacts
  and SLSA provenance

### End-to-end with Music Assistant (manual, post-release)
1. Install wheel into MA dev env
2. Point `ma-provider-yandex-music` at the library (editable dep)
3. Run MA, perform QR login, play a track end-to-end

---

## Open decisions resolved

- **Package name:** `ya-passport-auth`
- **Release scope for 0.1.0:** full API (QR + session refresh + quasar CSRF + glagol + account)
- **TLS SPKI pinning:** included in v1 API, opt-in (default `None`)
- **Docs:** README + SECURITY.md only in v1; mkdocs deferred
