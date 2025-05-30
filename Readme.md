# Gatekeeper: HTTP Middleware for Go Security and Control

Gatekeeper is a flexible and performant Go middleware library designed to enhance the security and control of your web applications. It offers seamless integration with the standard `net/http` library and popular Go web frameworks, providing essential security features out-of-the-box.

## Features

Gatekeeper provides four key security and control features:

1.  **User-Agent Blacklisting/Whitelisting:**
    *   **Purpose:** Block or allow requests based on the `User-Agent` header.
    *   **Configuration:** Define lists of exact User-Agent strings or regular expression patterns. Operates in `BLACKLIST` (block if matched) or `WHITELIST` (allow only if matched) mode.

2.  **IP Address Blacklisting/Whitelisting:**
    *   **Purpose:** Control access based on client IP address.
    *   **Configuration:** Define lists of individual IP addresses or CIDR ranges. Operates in `BLACKLIST` or `WHITELIST` mode. Supports trusting `X-Forwarded-For` / `X-Real-IP` headers from configured trusted proxies.

3.  **IP Address Rate Limiting (with Exceptions):**
    *   **Purpose:** Prevent abuse and brute-force attacks by limiting request rates per IP.
    *   **Configuration:** Define requests per period (e.g., 100 requests/minute).
    *   **Storage:** Defaults to an in-memory store (suitable for single instances). Pluggable `RateLimiterStore` interface allows for custom backends (e.g., Redis, Memcached) for distributed environments.
    *   **Exceptions:** Whitelist specific IPs/CIDRs or URL route patterns to bypass or have different rate limits.

4.  **Profanity Firewall (with Whitelisting):**
    *   **Purpose:** Filter requests containing undesirable language.
    *   **Configuration:** Define lists of profane words/phrases and a whitelist of words to ignore (e.g., "Scunthorpe").
    *   **Scope:** Can check query parameters, form data (urlencoded/multipart), and JSON request bodies.

## Installation

```bash
go get github.com/4nkitd/gatekeeper
```

## Quick Start (Standard Library `net/http`)

```go
package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/4nkitd/gatekeeper" // Use your actual module path
)

func main() {
	// Configure Gatekeeper
	gk, err := gatekeeper.New(gatekeeper.Config{
		IPPolicy: &gatekeeper.IPPolicyConfig{
			Mode:    gatekeeper.ModeBlacklist,
			IPs:     []string{"1.2.3.4"}, // Block this specific IP
			CIDRs:   []string{"5.6.0.0/16"}, // Block this CIDR range
		},
		UserAgentPolicy: &gatekeeper.UserAgentPolicyConfig{
			Mode:     gatekeeper.ModeBlacklist,
			Patterns: []string{`^EvilBot/.*`}, // Block User-Agents matching this regex
		},
		RateLimiter: &gatekeeper.RateLimiterConfig{
			Requests: 60,
			Period:   1 * time.Minute, // 60 requests per minute per IP
			Exceptions: &gatekeeper.RateLimiterExceptions{
				IPWhitelist: []string{"127.0.0.1"}, // Localhost bypasses rate limiting
			},
		},
		ProfanityFilter: &gatekeeper.ProfanityFilterConfig{
			BlockWords:       []string{"badword", "curse"},
			AllowWords:       []string{"scunthorpe"}, // Example for context
			CheckQueryParams: true,
			CheckJSONBody:    true,
		},
		DefaultBlockStatusCode: http.StatusForbidden,
	})
	if err != nil {
		log.Fatalf("Failed to initialize Gatekeeper: %v", err)
	}

	// Your main handler
	myHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, you've passed Gatekeeper!")
	})

	// Apply all configured Gatekeeper protections
	protectedHandler := gk.Protect(myHandler)

	// Or apply policies individually:
	// handler := myHandler
	// if gk.ConfiguredProfanityPolicy() { // Example of checking if a policy is configured
	//     handler = gk.ProfanityPolicy(handler)
	// }
	// if gk.ConfiguredRateLimiter() {
	//     handler = gk.RateLimit(handler)
	// }
	// ... and so on for IPPolicy and UserAgentPolicy

	http.Handle("/", protectedHandler)

	log.Println("Server starting on :8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
```

## Supported Frameworks

Gatekeeper provides middleware adapters for popular Go web frameworks:

*   **`net/http`** (Standard Library): `func(http.Handler) http.Handler`
*   **Gin**: `github.com/4nkitd/gatekeeper/adapter/ginadapter` provides `gin.HandlerFunc`
    ```go
    import "github.com/4nkitd/gatekeeper/adapter/ginadapter"
    // ...
    r.Use(ginadapter.IPPolicy(gk)) // gk is your *gatekeeper.Gatekeeper instance
    r.Use(ginadapter.RateLimit(gk))
    // Or apply all with a single adapter (if provided)
    // r.Use(ginadapter.ProtectAll(gk))
    ```
*   **Echo**: `github.com/4nkitd/gatekeeper/adapter/echoadapter` provides `echo.MiddlewareFunc`
*   **Fiber**: `github.com/4nkitd/gatekeeper/adapter/fiberadapter` provides `fiber.Handler`
*   **Chi**: Compatible with standard `net/http` middleware.

See the `adapter/` directory and specific framework examples for detailed usage.

## Configuration Options

Gatekeeper is configured using the `gatekeeper.Config` struct passed to `gatekeeper.New()`.

```go
type Config struct {
    UserAgentPolicy *UserAgentPolicyConfig
    IPPolicy        *IPPolicyConfig
    RateLimiter     *RateLimiterConfig
    ProfanityFilter *ProfanityFilterConfig

    Logger                 *log.Logger // Optional: Custom logger
    DefaultBlockStatusCode int         // Optional: Defaults to 403 Forbidden
    DefaultBlockMessage    string      // Optional: Defaults to "Forbidden"
}
```

### User-Agent Policy (`UserAgentPolicyConfig`)

*   `Mode`: `gatekeeper.ModeBlacklist` or `gatekeeper.ModeWhitelist`.
*   `Exact`: `[]string` of exact User-Agent strings (case-insensitive match).
*   `Patterns`: `[]string` of regular expressions to match User-Agents (case-sensitive by default, use `(?i)` in regex for insensitivity).

### IP Policy (`IPPolicyConfig`)

*   `Mode`: `gatekeeper.ModeBlacklist` or `gatekeeper.ModeWhitelist`.
*   `IPs`: `[]string` of individual IP addresses (e.g., "1.2.3.4").
*   `CIDRs`: `[]string` of IP ranges in CIDR notation (e.g., "10.0.0.0/8").
*   `TrustProxyHeaders`: `bool` (default `false`). If `true`, attempts to get client IP from `X-Forwarded-For` or `X-Real-IP`.
*   `TrustedProxies`: `[]string` of trusted proxy IPs/CIDRs. If `TrustProxyHeaders` is true, headers are only trusted if the direct connection is from one of these proxies. If empty and `TrustProxyHeaders` is true, headers from private IPs are typically trusted.

### Rate Limiter (`RateLimiterConfig`)

*   `Requests`: `int64` - Maximum number of requests allowed.
*   `Period`: `time.Duration` - The time window for the request limit (e.g., `1 * time.Minute`).
*   `Store`: `gatekeeper.RateLimiterStore` - Storage backend. Defaults to `store.NewMemoryStore()`. Implement this interface for custom stores (e.g., Redis).
*   `LimitExceededMessage`: `string` (default "Too Many Requests").
*   `LimitExceededStatusCode`: `int` (default `http.StatusTooManyRequests`).
*   `Exceptions`: `*RateLimiterExceptions`
    *   `IPWhitelist`: `[]string` of IPs/CIDRs exempt from rate limiting.
    *   `RouteWhitelistPatterns`: `[]string` of regex patterns for URL paths exempt from rate limiting.

### Profanity Filter (`ProfanityFilterConfig`)

*   `BlockWords`: `[]string` of words/phrases to block (case-insensitive).
*   `AllowWords`: `[]string` of words/phrases that, if matched as a `BlockWord`, should be allowed (e.g., if "hell" is blocked, "hello" might still trigger; "hell" could be in `AllowWords` if it's part of an acceptable compound word in your context, or the `BlockWords` should be more specific. The "Scunthorpe problem" can be tricky; `AllowWords` helps for exact `BlockWords` found within larger, acceptable strings if the `BlockWord` itself is allowed).
*   `CheckQueryParams`: `bool` - Scan URL query parameters.
*   `CheckFormFields`: `bool` - Scan `application/x-www-form-urlencoded` and `multipart/form-data` fields.
*   `CheckJSONBody`: `bool` - Scan JSON request bodies.
*   `BlockedMessage`: `string` (default "Bad Request").
*   `BlockedStatusCode`: `int` (default `http.StatusBadRequest`).

## Rate Limiter Store

The rate limiter defaults to an in-memory store. For distributed systems, you'll want to implement the `RateLimiterStore` interface using a shared backend like Redis or Memcached.

```go
package store

type RateLimiterStore interface {
    Allow(key string, limit int64, window time.Duration) (allowed bool, retryAfter time.Duration, err error)
    Cleanup() // Optional, for stores that need explicit cleanup
}
```

## Order of Middleware Execution

When using `gk.Protect(handler)`, the middleware is applied in the following default order (from outermost to innermost):

1.  IP Policy
2.  User-Agent Policy
3.  Rate Limiter
4.  Profanity Filter

You can also apply them individually in any order you prefer:

```go
handler = gk.IPPolicy(handler)
handler = gk.UserAgentPolicy(handler)
// ...etc.
```

## Logging

Gatekeeper uses the standard `log` package by default, prefixed with `[Gatekeeper]`. You can provide your own `*log.Logger` instance in `gatekeeper.Config.Logger`.

## Contributing

Contributions are welcome! Please feel free to submit issues, fork the repository, and send pull requests.

1.  Fork the repository.
2.  Create your feature branch (`git checkout -b feature/my-new-feature`).
3.  Commit your changes (`git commit -am 'Add some feature'`).
4.  Push to the branch (`git push origin feature/my-new-feature`).
5.  Create a new Pull Request.
