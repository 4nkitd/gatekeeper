package gatekeeper

import (
	"log"
	"os"
	"strings"
	"testing"
)

// testLogger returns a logger that logs to the test's t.Log.
func testLogger(t *testing.T) *log.Logger {
	// Using a more unique prefix to avoid potential collisions if other packages also log
	// and to make it clear these logs are from gatekeeper tests.
	return log.New(&testLogWriter{t}, "[GK_TEST] ", 0) // No flags for cleaner test output
}

// testLogWriter adapts testing.T to io.Writer for log.New.
type testLogWriter struct {
	t *testing.T
}

// Write sends the log output to t.Log(), trimming whitespace.
func (tlw *testLogWriter) Write(p []byte) (n int, err error) {
	// TrimSpace to remove leading/trailing newlines often added by log package
	tlw.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}

// Helper function to get environment variables with a fallback
// Useful for tests that might depend on optional environment configurations.
func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}
