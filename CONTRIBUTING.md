# Contributing to gatekeeper

A Go HTTP middleware library: IP / User-Agent / Referer policies, rate limiting, profanity filter.

## Dev setup

Prereqs:

- Go 1.21+

```bash
git clone https://github.com/4nkitd/gatekeeper.git
cd gatekeeper
go mod download
go build ./...
```

## Running tests

```bash
go test ./...
go test -race ./...
go test -cover ./...
```

The library itself has tests for each policy (`*_test.go`). Examples under `example/` are runnable programs but not test targets.

## Running examples

```bash
# Basic Echo integration
cd example/echo && go run .

# Echo with hot-reload config
cd example/echo-dynamic && go run .

# Config watcher demo
cd example/config-watcher && go run .
```

## Project layout

```
gatekeeper/
├── gatekeeper.go               # main Config + New() entry
├── ip_policy.go                # IP blacklist/whitelist (CIDR-aware)
├── user_agent_policy.go        # UA exact + regex matching
├── referer_policy.go           # Referer policy
├── rate_limiter.go             # Rate limiter with pluggable store
├── profanity_filter.go         # Body / query / form profanity check
├── echo_middleware.go          # native Echo middleware adapter
├── config_watcher.go           # hot-reload from file
├── store/                      # RateLimiterStore implementations
├── internal/utils/             # helper code
├── example/
│   ├── echo/                   # basic Echo integration
│   ├── echo-dynamic/           # Echo with dynamic config reload
│   └── config-watcher/         # config watcher tutorial
└── docs/                       # extended docs
```

## Adding a new policy

1. Add `<policy>.go` and `<policy>_test.go` at the repo root
2. Add a `<Policy>Config` struct to the existing `Config`
3. Implement a middleware method `(g *Gatekeeper) <Policy>(next http.Handler) http.Handler`
4. Wire it into `gk.Protect()` in the right order (cheap checks before expensive ones)
5. Update README's Features / Configuration sections
6. CHANGELOG entry under `## [Unreleased]`

## Adding a new RateLimiterStore

Implement the `store.RateLimiterStore` interface in a new file under `store/`. Common choices: Redis, Memcached, Postgres.

```go
type RateLimiterStore interface {
    Allow(key string, limit int64, window time.Duration) (allowed bool, retryAfter time.Duration, err error)
    Cleanup()
}
```

## Branches and commits

- Branch from `master`: `feat/<name>`, `fix/<name>`, `docs/<name>`.
- Conventional Commits encouraged.

## PR checklist

- [ ] `go build ./...` succeeds (must include `example/...`)
- [ ] `go vet ./...` clean
- [ ] `go test -race ./...` passes
- [ ] If touching a public function/struct, update README / docs
- [ ] CHANGELOG entry under `## [Unreleased]`

## Releases

Maintainers only. Tag `vX.Y.Z` (or `X.Y.Z` for legacy parity with `1.0.1`), push. Consumers can `go get github.com/4nkitd/gatekeeper@vX.Y.Z`.

## Reporting issues

[GitHub issues](https://github.com/4nkitd/gatekeeper/issues).
