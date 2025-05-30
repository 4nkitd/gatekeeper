# Configuration Reference

This document provides comprehensive documentation for all Gatekeeper configuration options.

## 📋 Main Configuration Structure

```go
type Config struct {
    UserAgentPolicy        *UserAgentPolicyConfig `json:"userAgentPolicy,omitempty"`
    IPPolicy              *IPPolicyConfig        `json:"ipPolicy,omitempty"`
    RefererPolicy         *RefererPolicyConfig   `json:"refererPolicy,omitempty"`
    RateLimiter           *RateLimiterConfig     `json:"rateLimiter,omitempty"`
    ProfanityFilter       *ProfanityFilterConfig `json:"profanityFilter,omitempty"`

    Logger                 *log.Logger `json:"-"`
    DefaultBlockStatusCode int         `json:"defaultBlockStatusCode,omitempty"`
    DefaultBlockMessage    string      `json:"defaultBlockMessage,omitempty"`
}
```

### Global Configuration Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Logger` | `*log.Logger` | Standard logger with `[Gatekeeper]` prefix | Custom logger for Gatekeeper events |
| `DefaultBlockStatusCode` | `int` | `403` (Forbidden) | Default HTTP status code for blocked requests |
| `DefaultBlockMessage` | `string` | `"Forbidden"` | Default response message for blocked requests |

## 🌐 IP Policy Configuration

Control access based on client IP addresses with support for proxy headers.

```go
type IPPolicyConfig struct {
    Mode              PolicyMode `json:"mode"`
    IPs               []string   `json:"ips"`
    CIDRs             []string   `json:"cidrs"`
    TrustProxyHeaders bool       `json:"trustProxyHeaders"`
    TrustedProxies    []string   `json:"trustedProxies"`
}
```

### IP Policy Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Mode` | `PolicyMode` | **Required** | `ModeBlacklist` or `ModeWhitelist` |
| `IPs` | `[]string` | `[]` | List of individual IP addresses (e.g., `"192.168.1.100"`) |
| `CIDRs` | `[]string` | `[]` | List of CIDR ranges (e.g., `"10.0.0.0/8"`) |
| `TrustProxyHeaders` | `bool` | `false` | Trust `X-Forwarded-For` and `X-Real-IP` headers |
| `TrustedProxies` | `[]string` | `[]` | IPs/CIDRs of trusted proxies (required if `TrustProxyHeaders` is true) |

### IP Policy Examples

```go
// Block specific malicious IPs
IPPolicy: &gatekeeper.IPPolicyConfig{
    Mode:  gatekeeper.ModeBlacklist,
    IPs:   []string{"192.168.1.100", "10.0.0.50"},
    CIDRs: []string{"172.16.0.0/16"},
}

// Allow only internal network
IPPolicy: &gatekeeper.IPPolicyConfig{
    Mode:  gatekeeper.ModeWhitelist,
    IPs:   []string{"127.0.0.1", "::1"},
    CIDRs: []string{"10.0.0.0/8", "192.168.0.0/16"},
}

// With proxy support (behind load balancer)
IPPolicy: &gatekeeper.IPPolicyConfig{
    Mode:              gatekeeper.ModeBlacklist,
    IPs:               []string{"1.2.3.4"},
    TrustProxyHeaders: true,
    TrustedProxies:    []string{"10.0.0.0/8", "172.16.0.0/12"},
}
```

## 👤 User-Agent Policy Configuration

Filter requests based on User-Agent headers to block bots, scrapers, and malicious clients.

```go
type UserAgentPolicyConfig struct {
    Mode     PolicyMode `json:"mode"`
    Exact    []string   `json:"exact"`
    Patterns []string   `json:"patterns"`
}
```

### User-Agent Policy Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Mode` | `PolicyMode` | **Required** | `ModeBlacklist` or `ModeWhitelist` |
| `Exact` | `[]string` | `[]` | Exact User-Agent strings (case-insensitive) |
| `Patterns` | `[]string` | `[]` | Regular expression patterns (case-sensitive by default) |

### User-Agent Policy Examples

```go
// Block known bad bots and scrapers
UserAgentPolicy: &gatekeeper.UserAgentPolicyConfig{
    Mode: gatekeeper.ModeBlacklist,
    Exact: []string{
        "BadBot/1.0",
        "EvilScraper/2.0",
        "MaliciousBot",
    },
    Patterns: []string{
        `^curl/.*`,                // Block all curl requests
        `^wget/.*`,                // Block all wget requests
        `(?i)^.*bot.*scanner.*$`,  // Block bot scanners (case-insensitive)
        `(?i)^.*scraper.*$`,       // Block scrapers (case-insensitive)
        `(?i)^.*sqlmap.*$`,        // Block SQL injection tools
        `(?i)^.*nikto.*$`,         // Block vulnerability scanners
    },
}

// Allow only specific browsers
UserAgentPolicy: &gatekeeper.UserAgentPolicyConfig{
    Mode: gatekeeper.ModeWhitelist,
    Patterns: []string{
        `(?i)Mozilla.*Chrome.*`,   // Chrome browsers
        `(?i)Mozilla.*Firefox.*`,  // Firefox browsers
        `(?i)Mozilla.*Safari.*`,   // Safari browsers
    },
}
```

### Regular Expression Tips

- Use `(?i)` at the beginning for case-insensitive matching
- `^` matches the beginning of the string
- `$` matches the end of the string
- `.*` matches any characters
- Test your patterns thoroughly to avoid false positives

## 🔗 Referer Policy Configuration

Control access based on HTTP Referer headers to prevent hotlinking and block malicious referrers.

```go
type RefererPolicyConfig struct {
    Mode     PolicyMode `json:"mode"`
    Exact    []string   `json:"exact"`
    Patterns []string   `json:"patterns"`
}
```

### Referer Policy Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Mode` | `PolicyMode` | **Required** | `ModeBlacklist` or `ModeWhitelist` |
| `Exact` | `[]string` | `[]` | Exact Referer URLs (case-sensitive) |
| `Patterns` | `[]string` | `[]` | Regular expression patterns |

### Referer Policy Examples

```go
// Block malicious referrers and enforce HTTPS
RefererPolicy: &gatekeeper.RefererPolicyConfig{
    Mode: gatekeeper.ModeBlacklist,
    Exact: []string{
        "http://malicious-site.com",
        "https://spam-domain.net",
        "http://phishing-site.org",
    },
    Patterns: []string{
        `(?i).*evil\.com.*`,    // Block any referer containing evil.com
        `(?i).*phishing\..*`,   // Block phishing domains
        `(?i).*malware\..*`,    // Block malware-related domains
        `^http://.*`,           // Block all non-HTTPS referers
    },
}

// Allow only trusted domains
RefererPolicy: &gatekeeper.RefererPolicyConfig{
    Mode: gatekeeper.ModeWhitelist,
    Exact: []string{
        "https://trusted.com",
        "https://partner.site",
    },
    Patterns: []string{
        `(?i).*\.mycompany\.com.*`,      // Allow company subdomains
        `^https://[a-z]+\.safe\.org$`,   // Allow safe.org subdomains
    },
}
```

## ⏱️ Rate Limiter Configuration

Prevent abuse and DDoS attacks with flexible rate limiting and exception handling.

```go
type RateLimiterConfig struct {
    Requests               int64                  `json:"requests"`
    Period                 time.Duration          `json:"period"`
    Store                  store.RateLimiterStore `json:"-"`
    Exceptions             *RateLimiterExceptions `json:"exceptions,omitempty"`
    LimitExceededMessage   string                 `json:"limitExceededMessage,omitempty"`
    LimitExceededStatusCode int                   `json:"limitExceededStatusCode,omitempty"`
}

type RateLimiterExceptions struct {
    IPWhitelist            []string `json:"ipWhitelist"`
    RouteWhitelistPatterns []string `json:"routeWhitelistPatterns"`
}
```

### Rate Limiter Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `Requests` | `int64` | **Required** | Maximum requests allowed per period |
| `Period` | `time.Duration` | **Required** | Time window (e.g., `1 * time.Minute`) |
| `Store` | `store.RateLimiterStore` | `MemoryStore` | Storage backend for rate limiting data |
| `Exceptions` | `*RateLimiterExceptions` | `nil` | IP and route exceptions |
| `LimitExceededMessage` | `string` | `"Rate limit exceeded. Please slow down!"` | Message for rate-limited requests |
| `LimitExceededStatusCode` | `int` | `429` (Too Many Requests) | HTTP status for rate-limited requests |

### Rate Limiter Exception Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `IPWhitelist` | `[]string` | `[]` | IPs/CIDRs exempt from rate limiting |
| `RouteWhitelistPatterns` | `[]string` | `[]` | URL patterns exempt from rate limiting |

### Rate Limiter Examples

```go
// Basic rate limiting: 60 requests per minute
RateLimiter: &gatekeeper.RateLimiterConfig{
    Requests: 60,
    Period:   1 * time.Minute,
    Store:    store.NewMemoryStore(5 * time.Minute),
}

// With exceptions for localhost and health endpoints
RateLimiter: &gatekeeper.RateLimiterConfig{
    Requests: 100,
    Period:   1 * time.Minute,
    Store:    store.NewMemoryStore(10 * time.Minute),
    Exceptions: &gatekeeper.RateLimiterExceptions{
        IPWhitelist: []string{
            "127.0.0.1",    // Localhost
            "::1",          // IPv6 localhost
            "10.0.0.0/8",   // Internal network
        },
        RouteWhitelistPatterns: []string{
            `^/health$`,       // Health check
            `^/metrics$`,      // Metrics endpoint
            `^/static/.*`,     // Static assets
            `^/api/webhook$`,  // Webhook endpoint
        },
    },
    LimitExceededMessage:    "Too many requests. Please slow down!",
    LimitExceededStatusCode: http.StatusTooManyRequests,
}

// Strict rate limiting for API endpoints
RateLimiter: &gatekeeper.RateLimiterConfig{
    Requests: 30,
    Period:   30 * time.Second,
    Store:    store.NewMemoryStore(2 * time.Minute),
}
```

## 🚫 Profanity Filter Configuration

Content moderation to filter inappropriate language from user inputs.

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

### Profanity Filter Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `BlockWords` | `[]string` | `[]` | Words/phrases to block (case-insensitive) |
| `AllowWords` | `[]string` | `[]` | Words to explicitly allow (prevents false positives) |
| `CheckQueryParams` | `bool` | `false` | Scan URL query parameters |
| `CheckFormFields` | `bool` | `false` | Scan form data fields |
| `CheckJSONBody` | `bool` | `false` | Scan JSON request bodies |
| `BlockedMessage` | `string` | `"Content contains inappropriate language"` | Message for blocked content |
| `BlockedStatusCode` | `int` | `400` (Bad Request) | HTTP status for blocked content |

### Profanity Filter Examples

```go
// Basic profanity filtering
ProfanityFilter: &gatekeeper.ProfanityFilterConfig{
    BlockWords: []string{
        "badword",
        "spam",
        "offensive",
        "inappropriate",
        "malicious",
    },
    AllowWords: []string{
        "scunthorpe",  // Classic false positive example
        "assess",      // Contains "ass" but is legitimate
        "cassette",    // Another potential false positive
    },
    CheckQueryParams: true,
    CheckFormFields:  true,
    CheckJSONBody:    true,
}

// Comprehensive content moderation
ProfanityFilter: &gatekeeper.ProfanityFilterConfig{
    BlockWords: []string{
        // Basic profanity
        "badword", "spam", "junk",
        
        // Hate speech indicators
        "hate", "racist", "sexist",
        
        // Scam indicators
        "scam", "phishing", "malware",
        
        // Abuse indicators
        "abuse", "harassment", "threat",
    },
    AllowWords: []string{
        "assessment",   // Contains "ass"
        "classic",      // Contains potential trigger
        "passionate",   // Contains "ass"
    },
    CheckQueryParams:  true,
    CheckFormFields:   true,
    CheckJSONBody:     true,
    BlockedMessage:    "Your content violates our community guidelines",
    BlockedStatusCode: http.StatusBadRequest,
}
```

## 🔄 JSON Configuration

You can also configure Gatekeeper using JSON files for dynamic configuration:

```json
{
  "ipPolicy": {
    "mode": "BLACKLIST",
    "ips": ["192.168.1.100", "10.0.0.50"],
    "cidrs": ["172.16.0.0/16"],
    "trustProxyHeaders": true,
    "trustedProxies": ["127.0.0.1/32", "::1/128"]
  },
  "userAgentPolicy": {
    "mode": "BLACKLIST",
    "exact": ["BadBot/1.0", "EvilCrawler/2.0"],
    "patterns": ["^curl/.*", "(?i)^.*bot.*scanner.*$"]
  },
  "refererPolicy": {
    "mode": "WHITELIST",
    "exact": ["https://example.com"],
    "patterns": ["https://.*\\.example\\.com.*"]
  },
  "rateLimiter": {
    "requests": 100,
    "period": "1m",
    "exceptions": {
      "ipWhitelist": ["127.0.0.1"],
      "routeWhitelistPatterns": ["/health", "/metrics"]
    },
    "limitExceededMessage": "Rate limit exceeded",
    "limitExceededStatusCode": 429
  },
  "profanityFilter": {
    "blockWords": ["spam", "badword"],
    "allowWords": ["scunthorpe"],
    "checkQueryParams": true,
    "checkFormFields": true,
    "checkJsonBody": true,
    "blockedMessage": "Content not allowed",
    "blockedStatusCode": 400
  },
  "defaultBlockStatusCode": 403,
  "defaultBlockMessage": "Access denied"
}
```

Load JSON configuration:

```go
// Load from file
gk, err := gatekeeper.NewGatekeeperFromFile("config.json")

// Or with config watcher for hot reloading
watcher, err := gatekeeper.NewConfigWatcher("config.json", nil)
gk := watcher.GetGatekeeper()
watcher.Start()
```

## 🎯 Best Practices

### Security
- Use WHITELIST mode for maximum security when possible
- Regularly review and update IP blacklists
- Test regex patterns thoroughly to avoid false positives
- Monitor logs for blocked requests to identify threats

### Performance
- Use specific IP addresses instead of broad CIDR ranges when possible
- Optimize regex patterns for speed
- Consider Redis/Memcached for rate limiting in production
- Place cheaper checks (IP, User-Agent) before expensive ones

### Maintainability
- Use JSON configuration files for easier updates
- Implement configuration watching for hot reloads
- Document your security policies and review regularly
- Set up monitoring and alerting for security events

## 🔗 Related Topics

- [Framework Integration Guide](../guides/framework-integration.md)
- [Advanced Usage](../guides/advanced-usage.md)
- [Custom Stores](../guides/custom-stores.md)
- [Performance Tuning](../guides/performance.md)
