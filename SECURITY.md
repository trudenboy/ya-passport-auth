# Security Policy

## Reporting a vulnerability

If you discover a security issue, **please do not open a public issue.**

Instead, email the maintainer directly or use GitHub's private vulnerability
reporting feature at:
https://github.com/trudenboy/ya-passport-auth/security/advisories/new

You will receive an acknowledgement within 72 hours and a resolution timeline
within 7 days.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Threat model summary

| # | Threat | Mitigation |
|---|--------|------------|
| T1 | Token leak via logs/tracebacks | `SecretStr` redacts repr/str; `RedactingFilter` scrubs OAuth headers and 32+ hex runs |
| T2 | Token leak via pickling | `SecretStr.__reduce__` raises `TypeError` |
| T3 | TLS downgrade/MITM | `verify_tls` always True on library-owned sessions; SPKI pinning reserved for future release |
| T4 | SSRF via open redirect | `allow_redirects=False`; host allow-list |
| T5 | DoS via unbounded response | 1 MiB JSON cap, 2 MiB HTML cap |
| T6 | ReDoS on CSRF regex | Explicit character classes, non-greedy patterns; Hypothesis fuzz tested with deadline |
| T7 | Rate-limit ban | `AsyncMinDelayLimiter`; 429 -> `RateLimitedError` |
| T8 | Cookie leakage | Dedicated `CookieJar` per client |
| T9 | Supply-chain compromise | Hash-pinned lockfile, Dependabot, pip-audit |
| T10 | Secrets in repo | gitleaks pre-commit + CI |
| T11 | Typo-squatted dependency | Minimum version pins + hashed lockfile |
| T12 | Log injection | CR/LF replaced by `RedactingFilter` |
| T13 | Credential exposure via `__dict__` | `slots=True, frozen=True` on Credentials |
| T14 | Real tokens in test fixtures | Tokens match `test-token-*` pattern only |

## Out of scope

- Host compromise / memory scraping
- Side-channel timing attacks
- Encrypted at-rest storage (caller responsibility)
- CAPTCHA / anti-bot bypass
