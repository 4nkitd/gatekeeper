# Framework Integration Guide

Gatekeeper provides seamless integration with popular Go web frameworks. This guide covers integration patterns for different frameworks and provides practical examples.

## 🚀 Echo Framework (Built-in Support)

Gatekeeper provides native Echo middleware support with two convenient methods.

### Method 1: Create Instance Then Use Middleware

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
            Patterns: []string{`^curl/.*`, `(?i)^.*bot.*$`},
        },
        RateLimiter: &gatekeeper.RateLimiterConfig{
            Requests: 60,
            Period:   1 * time.Minute,
            Store:    store.NewMemoryStore(5 * time.Minute),
        },
    }
    
    // Create Gatekeeper instance
    gk, err := gatekeeper.New(config)
    if err != nil {
        e.Logger.Fatal("Failed to initialize Gatekeeper: ", err)
    }
    
    // Apply middleware
    e.Use(gk.EchoMiddleware())
    
    // Add other Echo middleware
    e.Use(middleware.Logger())
    e.Use(middleware.Recover())
    e.Use(middleware.CORS())
    
    // Define routes
    e.GET("/", func(c echo.Context) error {
        return c.JSON(http.StatusOK, map[string]string{
            "message": "Welcome! Security checks passed.",
        })
    })
    
    e.Logger.Fatal(e.Start(":8080"))
}
```

### Method 2: One-Step Creation

```go
func main() {
    e := echo.New()
    
    // Create and apply middleware in one step
    middleware, err := gatekeeper.EchoMiddlewareFromConfig(config)
    if err != nil {
        e.Logger.Fatal("Failed to initialize Gatekeeper: ", err)
    }
    e.Use(middleware)
    
    // Your routes...
    e.Logger.Fatal(e.Start(":8080"))
}
```

### Method 3: Dynamic Configuration with ConfigWatcher

```go
func main() {
    e := echo.New()
    
    // Use ConfigWatcher for hot reloading
    middleware, err := gatekeeper.EchoMiddlewareFromConfigWatcher("config.json", nil)
    if err != nil {
        e.Logger.Fatal("Failed to initialize Gatekeeper: ", err)
    }
    e.Use(middleware)
    
    // Your routes...
    e.Logger.Fatal(e.Start(":8080"))
}
```

## 🌐 Standard Library (net/http)

Perfect for simple HTTP servers and custom implementations.

### Basic Integration

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
            IPs:   []string{"1.2.3.4"},
        },
        RateLimiter: &gatekeeper.RateLimiterConfig{
            Requests: 60,
            Period:   1 * time.Minute,
            Store:    store.NewMemoryStore(5 * time.Minute),
        },
    })
    if err != nil {
        log.Fatalf("Failed to initialize Gatekeeper: %v", err)
    }

    // Your application handler
    myHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintln(w, "Hello! You've passed all security checks.")
    })

    // Apply all protections
    protectedHandler := gk.Protect(myHandler)

    // Start server
    http.Handle("/", protectedHandler)
    log.Println("Server starting on :8080...")
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

### Individual Policy Application

```go
func main() {
    gk, err := gatekeeper.New(config)
    if err != nil {
        log.Fatal(err)
    }

    // Apply policies individually for more control
    handler := myHandler
    if gk.ConfiguredProfanityFilter() {
        handler = gk.ProfanityPolicy(handler)
    }
    if gk.ConfiguredRateLimiter() {
        handler = gk.RateLimit(handler)
    }
    if gk.ConfiguredUserAgentPolicy() {
        handler = gk.UserAgentPolicy(handler)
    }
    if gk.ConfiguredIPPolicy() {
        handler = gk.IPPolicy(handler)
    }

    http.Handle("/", handler)
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

## 🍸 Gin Framework

Integration using Gin's middleware wrapper functionality.

### Basic Gin Integration

```go
package main

import (
    "net/http"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/4nkitd/gatekeeper"
    "github.com/4nkitd/gatekeeper/store"
)

func main() {
    r := gin.Default()
    
    // Configure Gatekeeper
    gk, err := gatekeeper.New(gatekeeper.Config{
        IPPolicy: &gatekeeper.IPPolicyConfig{
            Mode: gatekeeper.ModeBlacklist,
            IPs:  []string{"1.2.3.4"},
        },
        RateLimiter: &gatekeeper.RateLimiterConfig{
            Requests: 60,
            Period:   1 * time.Minute,
            Store:    store.NewMemoryStore(5 * time.Minute),
        },
    })
    if err != nil {
        panic(err)
    }
    
    // Wrap Gatekeeper middleware for Gin
    r.Use(gin.WrapH(gk.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // This will be called for each request that passes Gatekeeper
        // The actual Gin handler will be called next
    }))))
    
    // Define routes
    r.GET("/", func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{
            "message": "Welcome! Security checks passed.",
        })
    })
    
    r.Run(":8080")
}
```

### Advanced Gin Integration with Custom Middleware

```go
// Create a custom Gin middleware function
func GatekeeperMiddleware(gk *gatekeeper.Gatekeeper) gin.HandlerFunc {
    return gin.WrapH(gk.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Request passed all Gatekeeper checks
        // Continue to the next middleware/handler
    })))
}

func main() {
    r := gin.Default()
    
    gk, err := gatekeeper.New(config)
    if err != nil {
        panic(err)
    }
    
    // Use custom middleware
    r.Use(GatekeeperMiddleware(gk))
    
    // Your routes...
    r.Run(":8080")
}
```

## 🚀 Fiber Framework

Integration using Fiber's adapter for HTTP handlers.

### Basic Fiber Integration

```go
package main

import (
    "net/http"
    "time"

    "github.com/gofiber/fiber/v2"
    "github.com/gofiber/fiber/v2/middleware/adaptor"
    "github.com/4nkitd/gatekeeper"
    "github.com/4nkitd/gatekeeper/store"
)

func main() {
    app := fiber.New()
    
    // Configure Gatekeeper
    gk, err := gatekeeper.New(gatekeeper.Config{
        IPPolicy: &gatekeeper.IPPolicyConfig{
            Mode: gatekeeper.ModeBlacklist,
            IPs:  []string{"1.2.3.4"},
        },
        RateLimiter: &gatekeeper.RateLimiterConfig{
            Requests: 60,
            Period:   1 * time.Minute,
            Store:    store.NewMemoryStore(5 * time.Minute),
        },
    })
    if err != nil {
        panic(err)
    }
    
    // Use Fiber's HTTP middleware adapter
    app.Use(adaptor.HTTPMiddleware(gk.Protect))
    
    // Define routes
    app.Get("/", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{
            "message": "Welcome! Security checks passed.",
        })
    })
    
    app.Listen(":8080")
}
```

## 🌿 Chi Router

Integration with the lightweight Chi router.

### Basic Chi Integration

```go
package main

import (
    "net/http"
    "time"

    "github.com/go-chi/chi/v5"
    "github.com/go-chi/chi/v5/middleware"
    "github.com/4nkitd/gatekeeper"
    "github.com/4nkitd/gatekeeper/store"
)

func main() {
    r := chi.NewRouter()
    
    // Configure Gatekeeper
    gk, err := gatekeeper.New(gatekeeper.Config{
        IPPolicy: &gatekeeper.IPPolicyConfig{
            Mode: gatekeeper.ModeBlacklist,
            IPs:  []string{"1.2.3.4"},
        },
        RateLimiter: &gatekeeper.RateLimiterConfig{
            Requests: 60,
            Period:   1 * time.Minute,
            Store:    store.NewMemoryStore(5 * time.Minute),
        },
    })
    if err != nil {
        panic(err)
    }
    
    // Chi uses standard http.Handler middleware
    r.Use(gk.Protect)
    
    // Add other Chi middleware
    r.Use(middleware.Logger)
    r.Use(middleware.Recoverer)
    
    // Define routes
    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.Write([]byte(`{"message": "Welcome! Security checks passed."}`))
    })
    
    http.ListenAndServe(":8080", r)
}
```

## 🔧 Gorilla Mux

Integration with Gorilla Mux router.

### Basic Gorilla Mux Integration

```go
package main

import (
    "encoding/json"
    "net/http"
    "time"

    "github.com/gorilla/mux"
    "github.com/4nkitd/gatekeeper"
    "github.com/4nkitd/gatekeeper/store"
)

func main() {
    r := mux.NewRouter()
    
    // Configure Gatekeeper
    gk, err := gatekeeper.New(gatekeeper.Config{
        IPPolicy: &gatekeeper.IPPolicyConfig{
            Mode: gatekeeper.ModeBlacklist,
            IPs:  []string{"1.2.3.4"},
        },
        RateLimiter: &gatekeeper.RateLimiterConfig{
            Requests: 60,
            Period:   1 * time.Minute,
            Store:    store.NewMemoryStore(5 * time.Minute),
        },
    })
    if err != nil {
        panic(err)
    }
    
    // Apply Gatekeeper middleware
    r.Use(gk.Protect)
    
    // Define routes
    r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]string{
            "message": "Welcome! Security checks passed.",
        })
    })
    
    http.ListenAndServe(":8080", r)
}
```

## 🎯 Route-Specific Protection

Apply different security policies to different routes.

### Echo Route Groups

```go
func main() {
    e := echo.New()
    
    // Configure different Gatekeeper instances
    publicGK, _ := gatekeeper.New(gatekeeper.Config{
        RateLimiter: &gatekeeper.RateLimiterConfig{
            Requests: 100,
            Period:   1 * time.Minute,
        },
    })
    
    adminGK, _ := gatekeeper.New(gatekeeper.Config{
        IPPolicy: &gatekeeper.IPPolicyConfig{
            Mode: gatekeeper.ModeWhitelist,
            IPs:  []string{"127.0.0.1", "192.168.1.0/24"},
        },
        RateLimiter: &gatekeeper.RateLimiterConfig{
            Requests: 10,
            Period:   1 * time.Minute,
        },
    })
    
    // Public routes with basic protection
    public := e.Group("/api/v1")
    public.Use(publicGK.EchoMiddleware())
    public.GET("/posts", getPosts)
    public.GET("/users", getUsers)
    
    // Admin routes with strict protection
    admin := e.Group("/admin")
    admin.Use(adminGK.EchoMiddleware())
    admin.GET("/dashboard", adminDashboard)
    admin.POST("/users", createUser)
    
    e.Logger.Fatal(e.Start(":8080"))
}
```

### Standard Library Route-Specific Protection

```go
func main() {
    // Different protection levels
    publicGK, _ := gatekeeper.New(publicConfig)
    adminGK, _ := gatekeeper.New(adminConfig)
    
    // Apply to specific routes
    http.Handle("/api/", publicGK.Protect(http.HandlerFunc(apiHandler)))
    http.Handle("/admin/", adminGK.Protect(http.HandlerFunc(adminHandler)))
    http.Handle("/public/", http.HandlerFunc(publicHandler)) // No protection
    
    log.Fatal(http.ListenAndServe(":8080", nil))
}
```

## 🔄 Dynamic Configuration

Hot-reload configuration changes without restarting your application.

### Echo with ConfigWatcher

```go
func main() {
    e := echo.New()
    
    // Create ConfigWatcher for hot reloading
    watcher, err := gatekeeper.NewConfigWatcher("config.json", &gatekeeper.ConfigWatcherOptions{
        CheckInterval: 30 * time.Second,
    })
    if err != nil {
        e.Logger.Fatal("Failed to create config watcher: ", err)
    }
    
    // Start watching for config changes
    watcher.Start()
    defer watcher.Stop()
    
    // Use middleware that always uses latest config
    e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            // Get current Gatekeeper instance
            gk := watcher.GetGatekeeper()
            
            // Create temporary HTTP handler
            httpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                c.SetRequest(r)
                if err := next(c); err != nil {
                    c.Error(err)
                }
            })
            
            // Apply current protection
            protectedHandler := gk.Protect(httpHandler)
            protectedHandler.ServeHTTP(c.Response().Writer, c.Request())
            
            return nil
        }
    })
    
    // Your routes...
    e.Logger.Fatal(e.Start(":8080"))
}
```

## 🔗 Best Practices by Framework

### Echo
- Use route groups for different protection levels
- Leverage Echo's built-in middleware for logging and recovery
- Consider using ConfigWatcher for dynamic updates

### Gin
- Wrap Gatekeeper in custom middleware for better integration
- Use Gin's middleware for JSON responses and error handling
- Be careful with middleware order

### Fiber
- Use adaptor.HTTPMiddleware for seamless integration
- Consider Fiber's built-in rate limiting for comparison
- Test thoroughly as Fiber uses fasthttp

### Chi/Gorilla Mux
- These work seamlessly with standard net/http patterns
- Use router groups for route-specific protection
- Easy to integrate with other standard middleware

## 🚀 Next Steps

- [Advanced Usage Guide](advanced-usage.md) - Performance optimization and monitoring
- [Configuration Reference](../reference/configuration.md) - Complete configuration options
- [Examples](../examples/) - Real-world integration examples