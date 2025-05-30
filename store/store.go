package store

import (
	"time"
)

// RateLimiterStore defines the interface for rate limiting storage.
type RateLimiterStore interface {
	// Allow checks if a key (e.g., IP address) is allowed to make a request.
	// It should increment the count for the key within the window.
	// Returns:
	// - bool: true if allowed, false if denied.
	// - time.Duration: if denied, the suggested Retry-After duration.
	// - error: if any error occurred during the operation.
	Allow(key string, limit int64, window time.Duration) (allowed bool, retryAfter time.Duration, err error)
	// Cleanup can be called periodically to remove stale entries.
	// Not all stores might need this (e.g., Redis with TTL).
	Cleanup()
}
