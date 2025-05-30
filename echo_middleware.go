package gatekeeper

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// EchoMiddleware returns an Echo middleware function that applies all configured Gatekeeper policies.
// This provides a seamless integration with the Echo framework.
//
// Usage:
//
//	gk, err := gatekeeper.New(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	e.Use(gk.EchoMiddleware())
func (gk *Gatekeeper) EchoMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Create an http.Handler that wraps the Echo handler
			httpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Update Echo's context with the potentially modified request
				c.SetRequest(r)

				// Call the next Echo handler in the chain
				if err := next(c); err != nil {
					// Let Echo handle the error through its error handler
					c.Error(err)
				}
			})

			// Apply Gatekeeper protection (IP, User-Agent, Rate Limiting, Profanity Filter)
			protectedHandler := gk.Protect(httpHandler)

			// Execute the protected handler
			// If Gatekeeper blocks the request, it will write directly to the response
			// If it allows the request, it will call our httpHandler above
			protectedHandler.ServeHTTP(c.Response().Writer, c.Request())

			return nil
		}
	}
}

// EchoMiddlewareFromConfig is a convenience function that creates a new Gatekeeper instance
// and returns an Echo middleware function in one step.
//
// Usage:
//
//	middleware, err := gatekeeper.EchoMiddlewareFromConfig(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	e.Use(middleware)
func EchoMiddlewareFromConfig(config Config) (echo.MiddlewareFunc, error) {
	gk, err := New(config)
	if err != nil {
		return nil, err
	}
	return gk.EchoMiddleware(), nil
}

// EchoMiddlewareFromConfigWatcher returns an Echo middleware that uses a ConfigWatcher
// for dynamic configuration updates. The middleware will always use the latest configuration.
//
// Usage:
//
//	watcher, err := gatekeeper.NewConfigWatcher("config.json", nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	watcher.Start()
//	defer watcher.Stop()
//
//	e.Use(gatekeeper.EchoMiddlewareFromConfigWatcher(watcher))
func EchoMiddlewareFromConfigWatcher(watcher *ConfigWatcher) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Get the current gatekeeper instance (thread-safe)
			gk := watcher.GetGatekeeper()

			// Create an http.Handler that wraps the Echo handler
			httpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Update Echo's context with the potentially modified request
				c.SetRequest(r)

				// Call the next Echo handler in the chain
				if err := next(c); err != nil {
					// Let Echo handle the error through its error handler
					c.Error(err)
				}
			})

			// Apply Gatekeeper protection using current config
			protectedHandler := gk.Protect(httpHandler)

			// Execute the protected handler
			protectedHandler.ServeHTTP(c.Response().Writer, c.Request())

			return nil
		}
	}
}

// EchoMiddlewareFromConfigFile creates an Echo middleware that loads configuration
// from a JSON file and enables hot reloading. This is the most convenient way to
// use dynamic configuration with Echo.
//
// Usage:
//
//	middleware, watcher, err := gatekeeper.EchoMiddlewareFromConfigFile("config.json", nil)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	watcher.Start()
//	defer watcher.Stop()
//
//	e.Use(middleware)
func EchoMiddlewareFromConfigFile(filePath string, options *ConfigWatcherOptions) (echo.MiddlewareFunc, *ConfigWatcher, error) {
	watcher, err := NewConfigWatcher(filePath, options)
	if err != nil {
		return nil, nil, err
	}

	middleware := EchoMiddlewareFromConfigWatcher(watcher)
	return middleware, watcher, nil
}
