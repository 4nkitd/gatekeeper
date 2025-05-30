package gatekeeper

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRefererPolicyBlacklist(t *testing.T) {
	config := Config{
		RefererPolicy: &RefererPolicyConfig{
			Mode: ModeBlacklist,
			Exact: []string{
				"http://malicious.com",
				"https://spam.site",
			},
			Patterns: []string{
				`(?i).*evil\.com.*`,
				`(?i).*phishing\..*`,
			},
		},
		DefaultBlockStatusCode: http.StatusForbidden,
		DefaultBlockMessage:    "Access denied",
	}

	gk, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create gatekeeper: %v", err)
	}

	handler := gk.RefererPolicy(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	tests := []struct {
		name           string
		referer        string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "No referer - should allow",
			referer:        "",
			expectedStatus: http.StatusOK,
			expectedBody:   "OK",
		},
		{
			name:           "Good referer - should allow",
			referer:        "https://google.com",
			expectedStatus: http.StatusOK,
			expectedBody:   "OK",
		},
		{
			name:           "Exact blacklisted referer - should block",
			referer:        "http://malicious.com",
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Access denied\n",
		},
		{
			name:           "Case insensitive exact match - should block",
			referer:        "HTTP://MALICIOUS.COM",
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Access denied\n",
		},
		{
			name:           "Pattern match - should block",
			referer:        "https://sub.evil.com/path",
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Access denied\n",
		},
		{
			name:           "Phishing pattern - should block",
			referer:        "http://fake.phishing.site",
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Access denied\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.referer != "" {
				req.Header.Set("Referer", tt.referer)
			}
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if w.Body.String() != tt.expectedBody {
				t.Errorf("Expected body %q, got %q", tt.expectedBody, w.Body.String())
			}
		})
	}
}

func TestRefererPolicyWhitelist(t *testing.T) {
	config := Config{
		RefererPolicy: &RefererPolicyConfig{
			Mode: ModeWhitelist,
			Exact: []string{
				"https://trusted.com",
				"https://partner.site",
			},
			Patterns: []string{
				`(?i).*\.mycompany\.com.*`,
				`^https://[a-z]+\.safe\.org$`,
			},
		},
		DefaultBlockStatusCode: http.StatusForbidden,
		DefaultBlockMessage:    "Access denied",
	}

	gk, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create gatekeeper: %v", err)
	}

	handler := gk.RefererPolicy(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))

	tests := []struct {
		name           string
		referer        string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "No referer - should block in whitelist mode",
			referer:        "",
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Access denied\n",
		},
		{
			name:           "Non-whitelisted referer - should block",
			referer:        "https://google.com",
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Access denied\n",
		},
		{
			name:           "Exact whitelisted referer - should allow",
			referer:        "https://trusted.com",
			expectedStatus: http.StatusOK,
			expectedBody:   "OK",
		},
		{
			name:           "Case insensitive exact match - should allow",
			referer:        "HTTPS://TRUSTED.COM",
			expectedStatus: http.StatusOK,
			expectedBody:   "OK",
		},
		{
			name:           "Pattern match company domain - should allow",
			referer:        "https://app.mycompany.com/dashboard",
			expectedStatus: http.StatusOK,
			expectedBody:   "OK",
		},
		{
			name:           "Pattern match safe.org - should allow",
			referer:        "https://docs.safe.org",
			expectedStatus: http.StatusOK,
			expectedBody:   "OK",
		},
		{
			name:           "Invalid safe.org subdomain - should block",
			referer:        "https://123.safe.org",
			expectedStatus: http.StatusForbidden,
			expectedBody:   "Access denied\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			if tt.referer != "" {
				req.Header.Set("Referer", tt.referer)
			}
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if w.Body.String() != tt.expectedBody {
				t.Errorf("Expected body %q, got %q", tt.expectedBody, w.Body.String())
			}
		})
	}
}

func TestRefererPolicyInvalidRegex(t *testing.T) {
	config := Config{
		RefererPolicy: &RefererPolicyConfig{
			Mode: ModeBlacklist,
			Patterns: []string{
				`[invalid regex`,
			},
		},
	}

	_, err := New(config)
	if err == nil {
		t.Error("Expected error for invalid regex pattern, got nil")
	}

	if !contains(err.Error(), "invalid referer regex pattern") {
		t.Errorf("Expected error message to contain 'invalid referer regex pattern', got: %v", err)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || (len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
