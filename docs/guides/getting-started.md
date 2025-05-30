# Getting Started with Gatekeeper

Gatekeeper is a powerful HTTP middleware library for Go that provides essential security and control features for web applications. This guide will help you get up and running quickly.

## 📦 Installation

Install Gatekeeper using Go modules:

```bash
go get github.com/4nkitd/gatekeeper
```

## 🎯 Core Concepts

Gatekeeper provides five main security policies:

1. **IP Policy** - Control access based on client IP addresses
2. **User-Agent Policy** - Filter requests based on User-Agent headers
3. **Referer Policy** - Control access based on HTTP Referer headers
4. **Rate Limiter** - Prevent abuse with request rate limiting
5. **Profanity Filter** - Content moderation for user inputs

Each policy can operate in two modes:
- **BLACKLIST** - Block if matched
- **WHITELIST** - Allow only if matched

## 🚀 Quick Start

### Basic Example with Standard Library

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
    config := gatekeeper.Config{
        // Block malicious IPs
        IPPolicy: &gatekeeper.IPPolicyConfig{
            Mode:  gatekeeper.ModeBlacklist,
            IPs:   []string{"1.2.3.4", "5.6.7.8"},
            CIDRs: []string{"192.168.100.0/24"},
        },
        
        // Block bots and scrapers
        UserAgentPolicy: &gatekeeper.UserAgentPolicyConfig{
            Mode: gatekeeper.ModeBlacklist,
            Patterns: []string{
                `^curl/.*`,               // Block curl
                `(?i)^.*bot.*$`,          // Block bots (case-insensitive)
                `(?i)^.*scraper.*$`,      // Block scrapers
            },
        },
        
        // Rate limiting: 60 requests per minute
        RateLimiter: &gatekeeper.RateLimiterConfig{
            Requests: 60,
            Period:   1 * time.Minute,
            Store:    store.NewMemoryStore(5 * time.Minute),
        },
        
        DefaultBlockStatusCode: http.StatusForbidden,
        DefaultBlockMessage:    "Access denied by security policy",
    }

    // Create Gatekeeper instance
    gk, err := gatekeeper.New(config)
    if err != nil {
        log.Fatalf("Failed to initialize Gatekeeper: %v", err)
    }

    // Your application handler
    myHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintln(w, "Hello! You've passed all security checks.")
    })

    // Apply Gatekeeper protection
    protectedHandler := gk.Protect(myHandler)

    // Start server
    http.Handle("/", protectedHandler)
    log.Println("Server starting on :8080...")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

### Echo Framework Example

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

    // Configure Gatekeeper
    config := gatekeeper.Config{
        IPPolicy: &gatekeeper.IPPolicyConfig{
            Mode:  gatekeeper.ModeBlacklist,
            IPs:   []string{"1.2.3.4"},
            CIDRs: []string{"192.168.100.0/24"},
        },
        UserAgentPolicy: &gatekeeper.UserAgentPolicyConfig{
            Mode: gatekeeper.ModeBlacklist,
            Exact: []string{"BadBot/1.0", "EvilScraper/2.0"},
            Patterns: []string{`^curl/.*`, `(?i)^.*bot.*scanner.*$`},
        },
        RateLimiter: &gatekeeper.RateLimiterConfig{
            Requests: 60,
            Period:   1 * time.Minute,
            Store:    store.NewMemoryStore(5 * time.Minute),
            Exceptions: &gatekeeper.RateLimiterExceptions{
                IPWhitelist: []string{"127.0.0.1", "::1"},
                RouteWhitelistPatterns: []string{`^/health$`, `^/metrics$`},
            },
        },
    }

    // Method 1: Create instance then use middleware
    gk, err := gatekeeper.New(config)
    if err != nil {
        e.Logger.Fatal("Failed to initialize Gatekeeper: ", err)
    }
    e.Use(gk.EchoMiddleware())

    // Method 2: One-step creation (alternative)
    // middleware, err := gatekeeper.EchoMiddlewareFromConfig(config)
    // if err != nil {
    //     e.Logger.Fatal("Failed to initialize Gatekeeper: ", err)
    // }
    // e.Use(middleware)

    // Add other middleware
    e.Use(middleware.Logger())
    e.Use(middleware.Recover())

    // Define routes
    e.GET("/", func(c echo.Context) error {
        return c.JSON(http.StatusOK, map[string]string{
            "message": "Welcome! Security checks passed.",
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

## 🧪 Testing Your Setup

After starting your server, test the security policies:

```bash
# Test normal request (should work)
curl http://localhost:8080/

# Test blocked User-Agent (should be blocked)
curl -H "User-Agent: curl/7.68.0" http://localhost:8080/

# Test rate limiting (run multiple times quickly)
for i in {1..70}; do curl -s http://localhost:8080/ >/dev/null; done
curl http://localhost:8080/  # This should be rate limited
```

## 📝 Configuration Basics

### Policy Modes

All policies support two modes:

- **BLACKLIST**: Block requests that match the criteria
- **WHITELIST**: Allow only requests that match the criteria

### Common Configuration Patterns

```go
// Block specific IPs and ranges
IPPolicy: &gatekeeper.IPPolicyConfig{
    Mode:  gatekeeper.ModeBlacklist,
    IPs:   []string{"192.168.1.100", "10.0.0.50"},
    CIDRs: []string{"172.16.0.0/16"},
}

// Allow only trusted IPs
IPPolicy: &gatekeeper.IPPolicyConfig{
    Mode:  gatekeeper.ModeWhitelist,
    IPs:   []string{"127.0.0.1", "::1"},
    CIDRs: []string{"10.0.0.0/8", "192.168.0.0/16"},
}

// Block known bots and scrapers
UserAgentPolicy: &gatekeeper.UserAgentPolicyConfig{
    Mode: gatekeeper.ModeBlacklist,
    Exact: []string{"BadBot/1.0", "EvilScraper/2.0"},
    Patterns: []string{
        `^curl/.*`,                // Block curl
        `^wget/.*`,                // Block wget
        `(?i)^.*bot.*scanner.*$`,  // Block bot scanners
        `(?i)^.*scraper.*$`,       // Block scrapers
    },
}

// Rate limiting with exceptions
RateLimiter: &gatekeeper.RateLimiterConfig{
    Requests: 100,                           // 100 requests
    Period:   1 * time.Minute,               // per minute
    Store:    store.NewMemoryStore(5 * time.Minute),
    Exceptions: &gatekeeper.RateLimiterExceptions{
        IPWhitelist: []string{"127.0.0.1"},   // Localhost exempt
        RouteWhitelistPatterns: []string{
            `^/health$`,    // Health checks
            `^/metrics$`,   // Monitoring
            `^/static/.*`,  // Static files
        },
    },
}
```

## 🔗 Next Steps

Now that you have Gatekeeper running, explore these topics:

- [Configuration Reference](../reference/configuration.md) - Complete configuration options
- [Framework Integration](framework-integration.md) - Integration with other frameworks
- [Security Policies](../reference/) - Detailed policy documentation
- [Examples](../examples/) - Real-world examples and use cases
- [Advanced Usage](advanced-usage.md) - Performance optimization and monitoring

## 🐛 Common Issues

### "Permission denied" errors
Make sure you're not blocking your own IP address in the IP policy.

### Rate limiting not working
Verify that the rate limiter store is properly configured and that your IP isn't in the whitelist.

### User-Agent blocking too aggressive
Review your regex patterns - use `(?i)` for case-insensitive matching and test patterns carefully.

### Performance concerns
Consider using Redis or Memcached for the rate limiter store in production environments.

---

**Ready to dive deeper?** Check out our [Configuration Reference](../reference/configuration.md) for complete documentation of all available options.
