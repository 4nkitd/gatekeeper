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
