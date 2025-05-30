package gatekeeper

import (
	// Added import for log
	"net/http"
	"net/http/httptest" // Added import for strings
	"testing"
)

func TestUserAgentPolicy(t *testing.T) {
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	tests := []struct {
		name               string
		config             UserAgentPolicyConfig
		userAgentHeader    string
		expectedStatusCode int
		expectBlocked      bool
	}{
		// Blacklist Mode Tests
		{
			name: "Blacklist - Exact Match Block",
			config: UserAgentPolicyConfig{
				Mode:  ModeBlacklist,
				Exact: []string{"BadBot/1.0"},
			},
			userAgentHeader:    "BadBot/1.0",
			expectedStatusCode: http.StatusForbidden,
			expectBlocked:      true,
		},
		{
			name: "Blacklist - Exact Match Case Insensitive Block",
			config: UserAgentPolicyConfig{
				Mode:  ModeBlacklist,
				Exact: []string{"badbot/1.0"},
			},
			userAgentHeader:    "BadBot/1.0",
			expectedStatusCode: http.StatusForbidden,
			expectBlocked:      true,
		},
		{
			name: "Blacklist - Pattern Match Block",
			config: UserAgentPolicyConfig{
				Mode:     ModeBlacklist,
				Patterns: []string{`^EvilCorpBot/.*`},
			},
			userAgentHeader:    "EvilCorpBot/2.1",
			expectedStatusCode: http.StatusForbidden,
			expectBlocked:      true,
		},
		{
			name: "Blacklist - No Match Allow",
			config: UserAgentPolicyConfig{
				Mode:  ModeBlacklist,
				Exact: []string{"BadBot/1.0"},
			},
			userAgentHeader:    "GoodBot/1.0",
			expectedStatusCode: http.StatusOK,
			expectBlocked:      false,
		},
		{
			name: "Blacklist - Empty User-Agent Allow",
			config: UserAgentPolicyConfig{
				Mode:  ModeBlacklist,
				Exact: []string{"BadBot/1.0"},
			},
			userAgentHeader:    "",
			expectedStatusCode: http.StatusOK,
			expectBlocked:      false,
		},

		// Whitelist Mode Tests
		{
			name: "Whitelist - Exact Match Allow",
			config: UserAgentPolicyConfig{
				Mode:  ModeWhitelist,
				Exact: []string{"GoodBot/1.0"},
			},
			userAgentHeader:    "GoodBot/1.0",
			expectedStatusCode: http.StatusOK,
			expectBlocked:      false,
		},
		{
			name: "Whitelist - Exact Match Case Insensitive Allow",
			config: UserAgentPolicyConfig{
				Mode:  ModeWhitelist,
				Exact: []string{"goodbot/1.0"},
			},
			userAgentHeader:    "GoodBot/1.0",
			expectedStatusCode: http.StatusOK,
			expectBlocked:      false,
		},
		{
			name: "Whitelist - Pattern Match Allow",
			config: UserAgentPolicyConfig{
				Mode:     ModeWhitelist,
				Patterns: []string{`^FriendlyBot/.*`},
			},
			userAgentHeader:    "FriendlyBot/3.0",
			expectedStatusCode: http.StatusOK,
			expectBlocked:      false,
		},
		{
			name: "Whitelist - No Exact Match Block",
			config: UserAgentPolicyConfig{
				Mode:  ModeWhitelist,
				Exact: []string{"GoodBot/1.0"},
			},
			userAgentHeader:    "AnotherBot/1.0",
			expectedStatusCode: http.StatusForbidden,
			expectBlocked:      true,
		},
		{
			name: "Whitelist - No Pattern Match Block",
			config: UserAgentPolicyConfig{
				Mode:     ModeWhitelist,
				Patterns: []string{`^FriendlyBot/.*`},
			},
			userAgentHeader:    "UnknownBot/1.0",
			expectedStatusCode: http.StatusForbidden,
			expectBlocked:      true,
		},
		{
			name: "Whitelist - Empty User-Agent Block",
			config: UserAgentPolicyConfig{
				Mode:  ModeWhitelist,
				Exact: []string{"GoodBot/1.0"},
			},
			userAgentHeader:    "",
			expectedStatusCode: http.StatusForbidden,
			expectBlocked:      true,
		},
		{
			name: "Whitelist - Pattern Case Sensitive (User Defined)",
			config: UserAgentPolicyConfig{
				Mode:     ModeWhitelist,
				Patterns: []string{`^CaseSensitiveBot`}, // No (?i) flag
			},
			userAgentHeader:    "casesensitivebot", // Should not match
			expectedStatusCode: http.StatusForbidden,
			expectBlocked:      true,
		},
		{
			name: "Whitelist - Pattern Case Insensitive (User Defined)",
			config: UserAgentPolicyConfig{
				Mode:     ModeWhitelist,
				Patterns: []string{`(?i)^CaseSensitiveBot`}, // With (?i) flag
			},
			userAgentHeader:    "casesensitivebot",
			expectedStatusCode: http.StatusOK,
			expectBlocked:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := Config{ // Create a full Config object
				UserAgentPolicy:        &tt.config,
				DefaultBlockStatusCode: http.StatusForbidden,
				DefaultBlockMessage:    "Blocked by Gatekeeper",
				Logger:                 testLogger(t),
			}

			gk, err := New(conf) // Use New for initialization
			if err != nil {
				// If policy creation is expected to fail (e.g. no patterns/exacts), handle here
				if !(len(tt.config.Exact) == 0 && len(tt.config.Patterns) == 0 && tt.config.Mode != "") {
					// Allow error if mode is set but no rules (which New should catch)
					// Or if specific tests expect an error from New()
				} else if len(tt.config.Exact) == 0 && len(tt.config.Patterns) == 0 {
					// This is a valid case for an error from newParsedUserAgentPolicy / New
					// if the mode was specified. If no mode, it's a passthrough.
					// The current tests don't explicitly test this path for successful policy creation.
				} else {
					t.Fatalf("New failed: %v", err)
				}
			}

			// If UserAgentPolicyConfig is nil or has no rules, gk.parsedUserAgentPolicy might be nil.
			// The UserAgentPolicy middleware method itself checks for nil gk.parsedUserAgentPolicy.
			if gk.parsedUserAgentPolicy == nil && (len(tt.config.Exact) > 0 || len(tt.config.Patterns) > 0) {
				t.Fatalf("gk.parsedUserAgentPolicy is nil even though config was provided with rules")
			}
			if gk.parsedUserAgentPolicy != nil && len(tt.config.Exact) == 0 && len(tt.config.Patterns) == 0 && tt.config.Mode != "" {
				// If a mode was set, but no rules, the policy should ideally be nil or effectively a no-op
				// This depends on New()'s behavior. For now, let's assume New() might create a non-nil policy
				// that correctly handles no rules.
			}

			req := httptest.NewRequest("GET", "/", nil)
			if tt.userAgentHeader != "" {
				req.Header.Set("User-Agent", tt.userAgentHeader)
			}

			rr := httptest.NewRecorder()
			handlerToTest := gk.UserAgentPolicy(dummyHandler)
			handlerToTest.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatusCode {
				t.Errorf("Expected status code %d, got %d", tt.expectedStatusCode, rr.Code)
			}

			if tt.expectBlocked && rr.Body.String() == "OK" {
				t.Errorf("Expected request to be blocked, but it was allowed.")
			}
			if !tt.expectBlocked && rr.Body.String() != "OK" {
				t.Errorf("Expected request to be allowed, but it was blocked. Body: %s", rr.Body.String())
			}
		})
	}
}
