# Changelog

All notable changes to this project are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `CHANGELOG.md` and `CONTRIBUTING.md`

### Fixed
- `example/` restructured into per-example subdirectories (`echo/`, `echo-dynamic/`, `config-watcher/`). Previously three files declared `package main` in the same directory, causing `go build ./...` to fail with "main redeclared". Verified `go build ./...` and `go test ./...` both clean.
- README pointer updated to the new example layout

---

## [1.0.1] — current tagged release

### Added
- Comprehensive documentation set + framework-integration guide (Echo, Gin, Fiber, Chi, Gorilla Mux)
- `ConfigWatcher` for dynamic config reloads with built-in middleware support for Echo
- Referer Policy: blacklist / whitelist with regex pattern matching
- Built-in Echo middleware adapter (`gk.EchoMiddleware()` and `gatekeeper.EchoMiddlewareFromConfig`)

---

## [1.0.0] — initial public

### Added
- User-Agent blacklist/whitelist (exact + regex)
- IP blacklist/whitelist (IPs + CIDRs, with optional X-Forwarded-For / X-Real-IP trust)
- IP rate limiting with pluggable `RateLimiterStore` (in-memory default)
- Profanity firewall (query params, form fields, JSON bodies; whitelist for false-positive words)
- `gk.Protect(handler)` convenience wrapper
- Echo / Gin / Fiber / Chi / net/http compatibility examples
- Configurable block status / message / logger
- Test suite for all five policies
- MIT license

[Unreleased]: https://github.com/4nkitd/gatekeeper/compare/1.0.1...HEAD
[1.0.1]: https://github.com/4nkitd/gatekeeper/releases/tag/1.0.1
