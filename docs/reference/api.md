# API Reference

This document provides comprehensive API documentation for all Gatekeeper functions, types, and interfaces.

## 📦 Core API

### Gatekeeper Creation

#### `NewGatekeeper(config *Config) (*Gatekeeper, error)`

Creates a new Gatekeeper instance with the provided configuration.

**Parameters:**
- `config` - Configuration struct containing all policy settings

**Returns:**
- `*Gatekeeper` - Configured Gatekeeper instance
- `error` - Configuration validation error, if any

**Example:**
```go
config := &gatekeeper.Config{
    IPPolicy: &gatekeeper.IPPolicyConfig{
        Mode: gatekeeper.ModeBlacklist,
        IPs:  []string{"192.168.1.100"},
    },
}

gk, err := gatekeeper.NewGatekeeper(config)
if err != nil {
    log.Fatal(err)
}
```

#### `NewGatekeeperFromFile(configPath string) (*Gatekeeper, error)`

Creates a Gatekeeper instance from a JSON configuration file.

**Parameters:**
- `configPath` - Path to JSON configuration file

**Returns:**
- `*Gatekeeper` - Configured Gatekeeper instance
- `error` - File read or configuration error

**Example:**
```go
gk, err := gatekeeper.NewGatekeeperFromFile("config.json")
if err != nil {
    log.Fatal(err)
}
```

### HTTP Middleware

#### `(g *Gatekeeper) HTTPMiddleware(next http.Handler) http.Handler`

Standard HTTP middleware for use with net/http and compatible frameworks.

**Parameters:**
- `next` - Next HTTP handler in the chain

**Returns:**
- `http.Handler` - Middleware-wrapped handler

**Example:**
```go
mux := http.NewServeMux()
mux.HandleFunc("/", homeHandler)

// Apply Gatekeeper middleware
server := &http.Server{
    Addr:    ":8080",
    Handler: gk.HTTPMiddleware(mux),
}
```

#### `(g *Gatekeeper) HandlerFunc(next http.HandlerFunc) http.HandlerFunc`

Handler function wrapper for simpler integration.

**Parameters:**
- `next` - Next HTTP handler function

**Returns:**
- `http.HandlerFunc` - Middleware-wrapped handler function

**Example:**
```go
http.HandleFunc("/api", gk.HandlerFunc(apiHandler))
```

### Echo Framework Integration

#### `(g *Gatekeeper) EchoMiddleware() echo.MiddlewareFunc`

Echo framework middleware function.

**Returns:**
- `echo.MiddlewareFunc` - Echo-compatible middleware

**Example:**
```go
e := echo.New()
e.Use(gk.EchoMiddleware())
e.GET("/", homeHandler)
```

### Request Processing

#### `(g *Gatekeeper) ProcessRequest(c echo.Context) error`

Process a request through all configured policies (Echo version).

**Parameters:**
- `c` - Echo context

**Returns:**
- `error` - Policy violation error or nil if allowed

#### `(g *Gatekeeper) ProcessHTTPRequest(r *http.Request) *PolicyViolation`

Process an HTTP request through all configured policies.

**Parameters:**
- `r` - HTTP request

**Returns:**
- `*PolicyViolation` - Violation details or nil if allowed

## 📊 Configuration Types

### Main Configuration

#### `Config`

Main configuration struct for Gatekeeper.

```go
type Config struct {
    UserAgentPolicy        *UserAgentPolicyConfig `json:"userAgentPolicy,omitempty"`
    IPPolicy              *IPPolicyConfig        `json:"ipPolicy,omitempty"`
    RefererPolicy         *RefererPolicyConfig   `json:"refererPolicy,omitempty"`
    RateLimiter           *RateLimiterConfig     `json:"rateLimiter,omitempty"`
    ProfanityFilter       *ProfanityFilterConfig `json:"profanityFilter,omitempty"`
    Logger                *log.Logger            `json:"-"`
    DefaultBlockStatusCode int                   `json:"defaultBlockStatusCode,omitempty"`
    DefaultBlockMessage    string                `json:"defaultBlockMessage,omitempty"`
}
```

### Policy Modes

#### `PolicyMode`

Enumeration for policy enforcement modes.

```go
type PolicyMode string

const (
    ModeBlacklist PolicyMode = "BLACKLIST"  // Block listed items
    ModeWhitelist PolicyMode = "WHITELIST"  // Allow only listed items
)
```

### IP Policy

#### `IPPolicyConfig`

Configuration for IP-based access control.

```go
type IPPolicyConfig struct {
    Mode              PolicyMode `json:"mode"`
    IPs               []string   `json:"ips"`
    CIDRs             []string   `json:"cidrs"`
    TrustProxyHeaders bool       `json:"trustProxyHeaders"`
    TrustedProxies    []string   `json:"trustedProxies"`
}
```

**Methods:**

##### `(policy *IPPolicyConfig) IsBlocked(ip string, headers http.Header) bool`

Check if an IP address is blocked by the policy.

**Parameters:**
- `ip` - Client IP address
- `headers` - HTTP headers (for proxy header extraction)

**Returns:**
- `bool` - True if IP should be blocked

### User-Agent Policy

#### `UserAgentPolicyConfig`

Configuration for User-Agent filtering.

```go
type UserAgentPolicyConfig struct {
    Mode     PolicyMode `json:"mode"`
    Exact    []string   `json:"exact"`
    Patterns []string   `json:"patterns"`
}
```

**Methods:**

##### `(policy *UserAgentPolicyConfig) IsBlocked(userAgent string) bool`

Check if a User-Agent string is blocked.

**Parameters:**
- `userAgent` - User-Agent header value

**Returns:**
- `bool` - True if User-Agent should be blocked

### Referer Policy

#### `RefererPolicyConfig`

Configuration for Referer header filtering.

```go
type RefererPolicyConfig struct {
    Mode     PolicyMode `json:"mode"`
    Exact    []string   `json:"exact"`
    Patterns []string   `json:"patterns"`
}
```

**Methods:**

##### `(policy *RefererPolicyConfig) IsBlocked(referer string) bool`

Check if a Referer URL is blocked.

**Parameters:**
- `referer` - Referer header value

**Returns:**
- `bool` - True if Referer should be blocked

### Rate Limiter

#### `RateLimiterConfig`

Configuration for rate limiting.

```go
type RateLimiterConfig struct {
    Requests               int64                  `json:"requests"`
    Period                 time.Duration          `json:"period"`
    Store                  store.RateLimiterStore `json:"-"`
    Exceptions             *RateLimiterExceptions `json:"exceptions,omitempty"`
    LimitExceededMessage   string                 `json:"limitExceededMessage,omitempty"`
    LimitExceededStatusCode int                   `json:"limitExceededStatusCode,omitempty"`
}
```

#### `RateLimiterExceptions`

Rate limiting exceptions configuration.

```go
type RateLimiterExceptions struct {
    IPWhitelist            []string `json:"ipWhitelist"`
    RouteWhitelistPatterns []string `json:"routeWhitelistPatterns"`
}
```

**Methods:**

##### `(rl *RateLimiterConfig) IsAllowed(ip, route string) bool`

Check if a request is allowed under rate limiting rules.

**Parameters:**
- `ip` - Client IP address
- `route` - Request URL path

**Returns:**
- `bool` - True if request is within rate limits

### Profanity Filter

#### `ProfanityFilterConfig`

Configuration for content profanity filtering.

```go
type ProfanityFilterConfig struct {
    BlockWords        []string `json:"blockWords"`
    AllowWords        []string `json:"allowWords"`
    CheckQueryParams  bool     `json:"checkQueryParams"`
    CheckFormFields   bool     `json:"checkFormFields"`
    CheckJSONBody     bool     `json:"checkJsonBody"`
    BlockedMessage    string   `json:"blockedMessage,omitempty"`
    BlockedStatusCode int      `json:"blockedStatusCode,omitempty"`
}
```

**Methods:**

##### `(pf *ProfanityFilterConfig) CheckRequest(r *http.Request) bool`

Check if request content contains blocked words.

**Parameters:**
- `r` - HTTP request to scan

**Returns:**
- `bool` - True if profanity detected

## 🔄 Configuration Watcher

### ConfigWatcher

Dynamic configuration management with hot reloading.

#### `NewConfigWatcher(configPath string, logger *log.Logger) (*ConfigWatcher, error)`

Create a new configuration file watcher.

**Parameters:**
- `configPath` - Path to JSON configuration file
- `logger` - Optional logger (uses default if nil)

**Returns:**
- `*ConfigWatcher` - Configuration watcher instance
- `error` - Initialization error

**Example:**
```go
watcher, err := gatekeeper.NewConfigWatcher("config.json", nil)
if err != nil {
    log.Fatal(err)
}

// Get current Gatekeeper instance
gk := watcher.GetGatekeeper()

// Start watching for changes
watcher.Start()

// Use with Echo
e.Use(gk.EchoMiddleware())

// Stop watching when done
defer watcher.Stop()
```

#### `(cw *ConfigWatcher) Start()`

Start watching the configuration file for changes.

#### `(cw *ConfigWatcher) Stop()`

Stop watching the configuration file.

#### `(cw *ConfigWatcher) GetGatekeeper() *Gatekeeper`

Get the current Gatekeeper instance (thread-safe).

**Returns:**
- `*Gatekeeper` - Current Gatekeeper instance

## 💾 Store Interface

### RateLimiterStore

Interface for rate limiter storage backends.

```go
type RateLimiterStore interface {
    Get(key string) (int64, time.Time, bool)
    Set(key string, count int64, expiry time.Time)
    Increment(key string, expiry time.Time) int64
    Delete(key string)
    Clear()
}
```

#### Built-in Implementations

##### `NewMemoryStore(cleanupInterval time.Duration) *MemoryStore`

Create a new in-memory rate limiter store.

**Parameters:**
- `cleanupInterval` - How often to clean expired entries

**Returns:**
- `*MemoryStore` - Memory-based store implementation

**Example:**
```go
store := store.NewMemoryStore(5 * time.Minute)

config := &gatekeeper.Config{
    RateLimiter: &gatekeeper.RateLimiterConfig{
        Requests: 100,
        Period:   1 * time.Minute,
        Store:    store,
    },
}
```

## ⚠️ Error Types

### PolicyViolation

Represents a policy violation with details.

```go
type PolicyViolation struct {
    Policy      string `json:"policy"`      // Policy name (e.g., "ip", "user-agent")
    Reason      string `json:"reason"`      // Violation reason
    StatusCode  int    `json:"statusCode"`  // HTTP status code to return
    Message     string `json:"message"`     // Response message
    ClientIP    string `json:"clientIP"`    // Client IP address
    UserAgent   string `json:"userAgent"`   // User-Agent header
    Referer     string `json:"referer"`     // Referer header
    RequestPath string `json:"requestPath"` // Request URL path
    Timestamp   string `json:"timestamp"`   // Violation timestamp
}
```

#### Methods

##### `(pv *PolicyViolation) Error() string`

Returns a string representation of the policy violation.

##### `(pv *PolicyViolation) ToJSON() ([]byte, error)`

Serialize the violation to JSON.

**Returns:**
- `[]byte` - JSON representation
- `error` - Serialization error

## 🔧 Utility Functions

### IP Utilities

#### `ParseIP(ipStr string) (net.IP, error)`

Parse an IP address string.

**Parameters:**
- `ipStr` - IP address string

**Returns:**
- `net.IP` - Parsed IP address
- `error` - Parse error

#### `GetClientIP(r *http.Request, trustProxy bool, trustedProxies []string) string`

Extract client IP from request, considering proxy headers.

**Parameters:**
- `r` - HTTP request
- `trustProxy` - Whether to trust proxy headers
- `trustedProxies` - List of trusted proxy IPs/CIDRs

**Returns:**
- `string` - Client IP address

#### `IsPrivateIP(ip net.IP) bool`

Check if an IP address is in a private range.

**Parameters:**
- `ip` - IP address to check

**Returns:**
- `bool` - True if IP is private

### Pattern Matching

#### `CompilePatterns(patterns []string) ([]*regexp.Regexp, error)`

Compile a list of regex patterns.

**Parameters:**
- `patterns` - List of regex pattern strings

**Returns:**
- `[]*regexp.Regexp` - Compiled regex patterns
- `error` - Compilation error

#### `MatchesAny(text string, patterns []*regexp.Regexp) bool`

Check if text matches any of the provided patterns.

**Parameters:**
- `text` - Text to match against
- `patterns` - Compiled regex patterns

**Returns:**
- `bool` - True if any pattern matches

## 📝 Logging

### Log Events

Gatekeeper logs the following events when a logger is configured:

- **Policy Violations:** When requests are blocked
- **Rate Limit Exceeded:** When rate limits are hit
- **Configuration Changes:** When config file is reloaded
- **Startup Events:** When policies are initialized
- **Error Events:** When errors occur during processing

### Log Format

```
[Gatekeeper] [LEVEL] MESSAGE - DETAILS
```

**Example Log Entries:**
```
[Gatekeeper] [INFO] IP Policy initialized with 5 blocked IPs
[Gatekeeper] [WARN] Request blocked by IP policy - IP: 192.168.1.100, Path: /api/users
[Gatekeeper] [INFO] Rate limit exceeded - IP: 10.0.0.50, Limit: 100/min
[Gatekeeper] [INFO] Configuration reloaded from config.json
[Gatekeeper] [ERROR] Failed to parse CIDR range: invalid-cidr
```

## 🔗 Related Documentation

- [Configuration Reference](configuration.md)
- [Getting Started Guide](../guides/getting-started.md)
- [Framework Integration](../guides/framework-integration.md)
- [Advanced Usage](../guides/advanced-usage.md)
- [Custom Stores](../guides/custom-stores.md)
