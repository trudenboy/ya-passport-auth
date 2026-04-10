# ya-passport-auth

> Async Yandex Passport (mobile) authentication library for Music Assistant providers.

**⚠️ Status:** early scaffolding. Not yet usable. See `PLAN.md` for the v0.1.0 roadmap.

## Security disclaimer

This library interacts with Yandex Passport using **public mobile OAuth client
IDs and secrets** extracted from official Yandex Android applications long ago.
These values are well-known and present in many open-source projects; they are
treated here as constants, not secrets. Do not use this library for anything
other than authenticating into your own Yandex account.

There is no official Yandex API for the mobile Passport flow. Endpoints,
response shapes, and regex patterns may break without notice.

## License

MIT. See `LICENSE` and `NOTICE` for third-party attribution.
