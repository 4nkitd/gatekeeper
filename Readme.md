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

## Quick Start Examples

### Standard Library (`net/http`)

```go
package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/4nkitd/gatekeeper"
	"github.com/4nkitd/gatekeeper/store"
)

func main() {
	// Configure Gatekeeper
	gk, err := gatekeeper.New(gatekeeper.Config{
		IPPolicy: &gatekeeper.IPPolicyConfig{
			Mode:  gatekeeper.ModeBlacklist,
			IPs:   []string{"1.2.3.4"},         // Block this specific IP
			CIDRs: []string{"192.168.100.0/24"}, // Block this CIDR range
		},
		UserAgentPolicy: &gatekeeper.UserAgentPolicyConfig{
			Mode:     gatekeeper.ModeBlacklist,
			Patterns: []string{`^curl/.*`, `(?i)^.*bot.*$`}, // Block curl and bots
		},
		RateLimiter: &gatekeeper.RateLimiterConfig{
			Requests: 60,
			Period:   1 * time.Minute, // 60 requests per minute per IP
			Store:    store.NewMemoryStore(5 * time.Minute),
			Exceptions: &gatekeeper.RateLimiterExceptions{
				IPWhitelist:            []string{"127.0.0.1", "::1"}, // Localhost bypasses rate limiting
				RouteWhitelistPatterns: []string{`^/health$`},         // Health endpoint exempt
			},
		},
		ProfanityFilter: &gatekeeper.ProfanityFilterConfig{
			BlockWords:       []string{"badword", "spam", "offensive"},
			AllowWords:       []string{"scunthorpe"}, // Avoid false positives
			CheckQueryParams: true,
			CheckFormFields:  true,
			CheckJSONBody:    true,
		},
		DefaultBlockStatusCode: http.StatusForbidden,
		DefaultBlockMessage:    "Access denied by security policy",
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

	http.Handle("/", protectedHandler)

	log.Println("Server starting on :8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
```

### Echo Framework

```go
package main

import (
	"net/http"
	"time"

	"github.com/4nkitd/gatekeeper"
	"github.com/4nkitd/gatekeeper/store"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
	e := echo.New()

	// Configure Gatekeeper with comprehensive security
	config := gatekeeper.Config{
		IPPolicy: &gatekeeper.IPPolicyConfig{
			Mode:  gatekeeper.ModeBlacklist,
			IPs:   []string{"1.2.3.4", "5.6.7.8"},
			CIDRs: []string{"192.168.100.0/24"},
		},
		UserAgentPolicy: &gatekeeper.UserAgentPolicyConfig{
			Mode: gatekeeper.ModeBlacklist,
			Exact: []string{"BadBot/1.0", "EvilScraper/2.0"},
			Patterns: []string{
				`^curl/.*`,               // Block curl
				`(?i)^.*bot.*scanner.*$`, // Block bot scanners
				`(?i)^.*scraper.*$`,      // Block scrapers
			},
		},
		RateLimiter: &gatekeeper.RateLimiterConfig{
			Requests: 60,
			Period:   1 * time.Minute,
			Store:    store.NewMemoryStore(5 * time.Minute),
			Exceptions: &gatekeeper.RateLimiterExceptions{
				IPWhitelist: []string{"127.0.0.1", "::1"},
				RouteWhitelistPatterns: []string{
					`^/health$`,   // Health checks
					`^/metrics$`,  // Monitoring
					`^/static/.*`, // Static assets
				},
			},
		},
		ProfanityFilter: &gatekeeper.ProfanityFilterConfig{
			BlockWords:       []string{"badword", "spam", "offensive"},
			CheckQueryParams: true,
			CheckFormFields:  true,
			CheckJSONBody:    true,
		},
		DefaultBlockStatusCode: http.StatusForbidden,
		DefaultBlockMessage:    "Access denied by security policy",
	}

	// Apply Gatekeeper middleware
	gk, err := gatekeeper.New(config)
	if err != nil {
		e.Logger.Fatal("Failed to initialize Gatekeeper: ", err)
	}
	e.Use(gk.EchoMiddleware())

	// Add other Echo middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Define routes
	e.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{
			"message": "Welcome! You passed all security checks.",
		})
	})

	e.GET("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{
			"status": "healthy",
		})
	})

	e.Logger.Fatal(e.Start(":8080"))
}
```

## Supported Frameworks

Gatekeeper provides built-in middleware support for popular Go web frameworks:

### Echo Framework (Built-in Support)

Gatekeeper provides native Echo middleware support with two convenient methods:

**Method 1: Create instance then use middleware**
```go
import (
    "github.com/4nkitd/gatekeeper"
    "github.com/labstack/echo/v4"
)

func main() {
    e := echo.New()
    
    // Create Gatekeeper instance
    gk, err := gatekeeper.New(config)
    if err != nil {
        log.Fatal(err)
    }
    
    // Apply middleware
    e.Use(gk.EchoMiddleware())
    
    // Your routes...
}
```

**Method 2: One-step creation**
```go
func main() {
    e := echo.New()
    
    // Create and apply middleware in one step
    middleware, err := gatekeeper.EchoMiddlewareFromConfig(config)
    if err != nil {
        log.Fatal(err)
    }
    e.Use(middleware)
    
    // Your routes...
}
```

### Other Frameworks

*   **`net/http`** (Standard Library): Use `gk.Protect(handler)` or individual policies
*   **Gin**: Use `gk.Protect()` with Gin's `WrapH()` function
*   **Fiber**: Use `gk.Protect()` with Fiber's `adaptor.HTTPHandler()`
*   **Chi**: Compatible with standard `net/http` middleware using `gk.Protect()`

For complete Echo example, see `example/echo.go` in the repository.

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
*   `Store`: `store.RateLimiterStore` - Storage backend. Defaults to `store.NewMemoryStore()` if not provided.
*   `LimitExceededMessage`: `string` (defaults to "Rate limit exceeded. Please slow down!").
*   `LimitExceededStatusCode`: `int` (defaults to `http.StatusTooManyRequests`).
*   `Exceptions`: `*RateLimiterExceptions`
    *   `IPWhitelist`: `[]string` of IPs/CIDRs exempt from rate limiting.
    *   `RouteWhitelistPatterns`: `[]string` of regex patterns for URL paths exempt from rate limiting (e.g., `^/health$`, `^/static/.*`).

### Profanity Filter (`ProfanityFilterConfig`)

*   `BlockWords`: `[]string` of words/phrases to block (case-insensitive).
*   `AllowWords`: `[]string` of words/phrases to explicitly allow, helping avoid false positives (e.g., "scunthorpe" problem).
*   `CheckQueryParams`: `bool` - Scan URL query parameters for profanity.
*   `CheckFormFields`: `bool` - Scan `application/x-www-form-urlencoded` and `multipart/form-data` fields.
*   `CheckJSONBody`: `bool` - Scan JSON request bodies for profanity.
*   `BlockedMessage`: `string` (defaults to "Content contains inappropriate language").
*   `BlockedStatusCode`: `int` (defaults to `http.StatusBadRequest`).

## Rate Limiter Store

The rate limiter uses an in-memory store by default (`store.NewMemoryStore()`). For distributed systems, you can implement the `store.RateLimiterStore` interface using a shared backend like Redis or Memcached.

```go
package store

type RateLimiterStore interface {
    Allow(key string, limit int64, window time.Duration) (allowed bool, retryAfter time.Duration, err error)
    Cleanup() // Optional, for stores that need explicit cleanup
}
```

Example custom store implementation:
```go
// RedisStore implements RateLimiterStore using Redis
type RedisStore struct {
    client *redis.Client
}

func (r *RedisStore) Allow(key string, limit int64, window time.Duration) (bool, time.Duration, error) {
    // Implement sliding window rate limiting using Redis
    // Return whether request is allowed and retry-after duration
}
```

## Advanced Usage

### Individual Policy Application

You can apply policies individually instead of using `gk.Protect()`:

```go
handler := myHandler
if gk.ConfiguredIPPolicy() {
    handler = gk.IPPolicy(handler)
}
if gk.ConfiguredUserAgentPolicy() {
    handler = gk.UserAgentPolicy(handler)
}
if gk.ConfiguredRateLimiter() {
    handler = gk.RateLimit(handler)
}
if gk.ConfiguredProfanityFilter() {
    handler = gk.ProfanityPolicy(handler)
}
```

### Framework Integration Examples

**Gin Framework:**
```go
import "github.com/gin-gonic/gin"

r := gin.Default()
gk, _ := gatekeeper.New(config)
r.Use(gin.WrapH(gk.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    // This will be called for each request that passes Gatekeeper
}))))
```

**Fiber Framework:**
```go
import "github.com/gofiber/fiber/v2/middleware/adaptor"

app := fiber.New()
gk, _ := gatekeeper.New(config)
app.Use(adaptor.HTTPMiddleware(gk.Protect))
```

### Testing Gatekeeper Policies

```bash
# Test User-Agent blocking
curl -H "User-Agent: curl/7.68.0" http://localhost:8080/
# Expected: Access denied by security policy

# Test with allowed User-Agent
curl -H "User-Agent: Chrome/91.0" http://localhost:8080/
# Expected: Normal response

# Test rate limiting (run multiple times quickly)
for i in {1..70}; do curl -s http://localhost:8080/ >/dev/null; done
curl http://localhost:8080/
# Expected: Rate limit exceeded after 60 requests

# Test profanity filter
curl -X POST -d "message=badword" http://localhost:8080/api/submit
# Expected: Content contains inappropriate language
```

## Order of Middleware Execution

When using `gk.Protect(handler)`, the middleware is applied in the following default order (from outermost to innermost):

1.  IP Policy - First line of defense, blocks malicious IPs
2.  User-Agent Policy - Blocks bots and scrapers  
3.  Rate Limiter - Prevents abuse and DDoS attacks
4.  Profanity Filter - Content moderation (innermost, closest to your handler)

This order ensures maximum security efficiency - cheaper checks (IP, User-Agent) happen before more expensive ones (rate limiting, content scanning).

## Logging

Gatekeeper uses the standard `log` package by default, prefixed with `[Gatekeeper]`. You can provide your own `*log.Logger` instance in `gatekeeper.Config.Logger`.

Example logs:
```
[Gatekeeper] Request blocked: GET /api/data from 1.2.3.4. Reason: IP address in blacklist
[Gatekeeper] Request blocked: POST /submit from 10.0.0.1. Reason: User-Agent 'curl/7.68.0' matches blocked pattern
[Gatekeeper] Request blocked: GET /api/data from 127.0.0.1. Reason: Rate limit exceeded (60 requests/minute)
[Gatekeeper] Request blocked: POST /comment from 192.168.1.100. Reason: Profanity detected in request body
```

## Contributing

Contributions are welcome! Please feel free to submit issues, fork the repository, and send pull requests.

1.  Fork the repository.
2.  Create your feature branch (`git checkout -b feature/my-new-feature`).
3.  Commit your changes (`git commit -am 'Add some feature'`).
4.  Push to the branch (`git push origin feature/my-new-feature`).
5.  Create a new Pull Request.
