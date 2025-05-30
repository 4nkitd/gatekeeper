package store

import (
	"sync"
	"time"
)

type requestRecord struct {
	timestamps []time.Time
}

// MemoryStore is an in-memory RateLimiterStore.
// Not recommended for distributed systems.
type MemoryStore struct {
	mu      sync.Mutex
	records map[string]*requestRecord
	// How long to keep records after they are no longer needed for rate limiting.
	// This is to ensure that records are cleaned up eventually.
	cleanupInterval time.Duration
	lastCleanup     time.Time
}

// NewMemoryStore creates a new in-memory store.
// The cleanupInterval determines how often stale records are potentially purged.
func NewMemoryStore(recordTTL time.Duration) *MemoryStore {
	ms := &MemoryStore{
		records:         make(map[string]*requestRecord),
		cleanupInterval: recordTTL, // Use recordTTL as a basis for cleanup frequency
		lastCleanup:     time.Now(),
	}
	// Optional: start a goroutine for periodic cleanup
	// go ms.periodicCleanup(recordTTL)
	return ms
}

func (ms *MemoryStore) Allow(key string, limit int64, window time.Duration) (bool, time.Duration, error) {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	now := time.Now()
	record, exists := ms.records[key]
	if !exists {
		record = &requestRecord{}
		ms.records[key] = record
	}

	// Remove timestamps older than the window
	validTimestamps := []time.Time{}
	windowStart := now.Add(-window)
	for _, ts := range record.timestamps {
		if ts.After(windowStart) {
			validTimestamps = append(validTimestamps, ts)
		}
	}
	record.timestamps = validTimestamps

	if int64(len(record.timestamps)) < limit {
		record.timestamps = append(record.timestamps, now)
		ms.tryCleanup(now) // Opportunistic cleanup
		return true, 0, nil
	}

	// Denied, calculate Retry-After
	// This is a simplified Retry-After, it should be the time until the oldest request in the window expires.
	var retryAfter time.Duration
	if len(record.timestamps) > 0 {
		oldestRelevantTimestamp := record.timestamps[0] // This is the one that will expire next
		retryAfter = oldestRelevantTimestamp.Add(window).Sub(now)
		if retryAfter < 0 {
			retryAfter = 0 // Should not happen if logic is correct
		}
	} else {
		retryAfter = window // Should not happen if limit > 0
	}

	ms.tryCleanup(now) // Opportunistic cleanup
	return false, retryAfter, nil
}

// tryCleanup performs cleanup if the cleanupInterval has passed.
// Must be called with the lock held.
func (ms *MemoryStore) tryCleanup(now time.Time) {
	if now.Sub(ms.lastCleanup) > ms.cleanupInterval {
		ms.performCleanupUnsafe(now)
		ms.lastCleanup = now
	}
}

// Cleanup removes stale records.
func (ms *MemoryStore) Cleanup() {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.performCleanupUnsafe(time.Now())
	ms.lastCleanup = time.Now()
}

// performCleanupUnsafe is the actual cleanup logic without locking.
// It iterates through all records and removes those whose most recent timestamp
// is older than the current time minus the cleanup interval (acting as a TTL).
func (ms *MemoryStore) performCleanupUnsafe(now time.Time) {
	// The window used for rate limiting is `window` from `Allow` method.
	// Here, `cleanupInterval` acts more like a grace period or TTL for the *record itself*
	// after its last relevant activity.
	// A simpler cleanup: remove records if all their timestamps are older than now - window - cleanupGrace.
	// A record is stale if its newest timestamp is older than `now - window - configured_cleanup_grace`.
	// Let's use cleanupInterval as that grace.
	// For a key to be deleted, all its timestamps must be older than `now - window_from_last_Allow_call - cleanupInterval`.
	// This is tricky because `window` is passed in `Allow`.
	// A simpler approach: if a record has no timestamps more recent than `now - cleanupInterval`, delete it.
	// This means if an IP stops making requests, its record will be deleted after `cleanupInterval`.
	staleThreshold := now.Add(-ms.cleanupInterval)
	for key, record := range ms.records {
		if len(record.timestamps) == 0 {
			delete(ms.records, key)
			continue
		}
		// Check the newest timestamp in the record
		newestTimestamp := record.timestamps[len(record.timestamps)-1]
		if newestTimestamp.Before(staleThreshold) {
			delete(ms.records, key)
		}
	}
}

// Optional: for background cleanup
// func (ms *MemoryStore) periodicCleanup(interval time.Duration) {
// 	ticker := time.NewTicker(interval)
// 	defer ticker.Stop()
// 	for range ticker.C {
// 		ms.Cleanup()
// 	}
// }
