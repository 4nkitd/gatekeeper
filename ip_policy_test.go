package gatekeeper

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/4nkitd/gatekeeper/internal/utils"
)

func TestIPPolicy(t *testing.T) {
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	tests := []struct {
		name               string
		config             IPPolicyConfig
		remoteAddr         string // Simulates r.RemoteAddr
		xForwardedFor      string // Simulates X-Forwarded-For header
		xRealIP            string // Simulates X-Real-IP header
		expectedStatusCode int
		expectBlocked      bool
	}{
		// Blacklist Mode Tests
		{
			name: "Blacklist - Exact IP Match Block",
			config: IPPolicyConfig{
				Mode: ModeBlacklist,
				IPs:  []string{"1.2.3.4"},
			},
			remoteAddr:         "1.2.3.4:12345",
			expectedStatusCode: http.StatusForbidden,
			expectBlocked:      true,
		},
		{
			name: "Blacklist - CIDR Match Block",
			config: IPPolicyConfig{
				Mode:  ModeBlacklist,
				CIDRs: []string{"1.2.0.0/16"},
			},
			remoteAddr:         "1.2.3.4:12345",
			expectedStatusCode: http.StatusForbidden,
			expectBlocked:      true,
		},
		{
			name: "Blacklist - No Match Allow",
			config: IPPolicyConfig{
				Mode: ModeBlacklist,
				IPs:  []string{"1.1.1.1"},
			},
			remoteAddr:         "2.2.2.2:12345",
			expectedStatusCode: http.StatusOK,
			expectBlocked:      false,
		},
		{
			name: "Blacklist - X-Forwarded-For Trusted Proxy Block",
			config: IPPolicyConfig{
				Mode:              ModeBlacklist,
				IPs:               []string{"10.0.0.1"}, // This is the actual client IP
				TrustProxyHeaders: true,
				TrustedProxies:    []string{"192.168.1.1/32"}, // The proxy server
			},
			remoteAddr:         "192.168.1.1:12345",    // Request comes from trusted proxy
			xForwardedFor:      "10.0.0.1, 172.16.0.1", // Actual client IP is 10.0.0.1
			expectedStatusCode: http.StatusForbidden,
			expectBlocked:      true,
		},
		{
			name: "Blacklist - X-Forwarded-For Untrusted Proxy Allow (uses RemoteAddr)",
			config: IPPolicyConfig{
				Mode:              ModeBlacklist,
				IPs:               []string{"10.0.0.1"}, // This is the actual client IP
				TrustProxyHeaders: true,
				TrustedProxies:    []string{"192.168.1.100/32"}, // Different trusted proxy
			},
			remoteAddr:         "192.168.1.2:12345", // Request comes from untrusted proxy
			xForwardedFor:      "10.0.0.1, 172.16.0.1",
			expectedStatusCode: http.StatusOK, // RemoteAddr (192.168.1.2) is not blacklisted
			expectBlocked:      false,
		},
		{
			name: "Blacklist - X-Real-IP Trusted Proxy Block",
			config: IPPolicyConfig{
				Mode:              ModeBlacklist,
				IPs:               []string{"10.0.0.2"},
				TrustProxyHeaders: true,
				TrustedProxies:    []string{"192.168.1.1/32"},
			},
			remoteAddr:         "192.168.1.1:12345",
			xRealIP:            "10.0.0.2",
			expectedStatusCode: http.StatusForbidden,
			expectBlocked:      true,
		},

		// Whitelist Mode Tests
		{
			name: "Whitelist - Exact IP Match Allow",
			config: IPPolicyConfig{
				Mode: ModeWhitelist,
				IPs:  []string{"1.2.3.4"},
			},
			remoteAddr:         "1.2.3.4:12345",
			expectedStatusCode: http.StatusOK,
			expectBlocked:      false,
		},
		{
			name: "Whitelist - CIDR Match Allow",
			config: IPPolicyConfig{
				Mode:  ModeWhitelist,
				CIDRs: []string{"1.2.0.0/16"},
			},
			remoteAddr:         "1.2.3.4:12345",
			expectedStatusCode: http.StatusOK,
			expectBlocked:      false,
		},
		{
			name: "Whitelist - No Match Block",
			config: IPPolicyConfig{
				Mode: ModeWhitelist,
				IPs:  []string{"1.1.1.1"},
			},
			remoteAddr:         "2.2.2.2:12345",
			expectedStatusCode: http.StatusForbidden,
			expectBlocked:      true,
		},
		{
			name: "Whitelist - X-Forwarded-For Trusted Proxy Allow",
			config: IPPolicyConfig{
				Mode:              ModeWhitelist,
				IPs:               []string{"10.0.0.1"},
				TrustProxyHeaders: true,
				TrustedProxies:    []string{"192.168.1.1/32"},
			},
			remoteAddr:         "192.168.1.1:12345",
			xForwardedFor:      "10.0.0.1",
			expectedStatusCode: http.StatusOK,
			expectBlocked:      false,
		},
		{
			name: "Whitelist - X-Forwarded-For Untrusted Proxy Block (uses RemoteAddr)",
			config: IPPolicyConfig{
				Mode:              ModeWhitelist,
				IPs:               []string{"10.0.0.1"}, // Actual client IP
				TrustProxyHeaders: true,
				TrustedProxies:    []string{"192.168.1.100/32"},
			},
			remoteAddr:         "192.168.1.2:12345", // This IP is not whitelisted
			xForwardedFor:      "10.0.0.1",
			expectedStatusCode: http.StatusForbidden,
			expectBlocked:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conf := Config{
				IPPolicy:               &tt.config,
				DefaultBlockStatusCode: http.StatusForbidden,
				DefaultBlockMessage:    "Blocked by Gatekeeper",
				Logger:                 testLogger(t),
			}
			gk, err := New(conf) // Use New for initialization
			if err != nil {
				// Allow error if mode is set but no rules (which New should catch)
				if !(len(tt.config.IPs) == 0 && len(tt.config.CIDRs) == 0 && tt.config.Mode != "") {
					t.Fatalf("New failed: %v", err)
				}
			}

			// Check if the policy was parsed as expected by New()
			if gk.IPPolicy == nil && (len(tt.config.IPs) > 0 || len(tt.config.CIDRs) > 0) {
				t.Fatalf("gk.IPPolicy is nil even though config was provided with rules")
			}

			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			rr := httptest.NewRecorder()
			handlerToTest := gk.IPPolicy(dummyHandler)
			handlerToTest.ServeHTTP(rr, req)

			if rr.Code != tt.expectedStatusCode {
				clientIP := ""
				// Attempt to get client IP for logging, handle potential nil gk.IPPolicy if New() failed as expected
				if gk.IPPolicy != nil && gk.config.IPPolicy != nil && gk.config.IPPolicy.TrustProxyHeaders {
					// Access TrustProxyHeaders from config and parsedTrustedProxies from the parsed policy
					clientIP_IP, _ := utils.GetClientIPFromRequest(req, gk.config.IPPolicy.TrustProxyHeaders, gk.parsedIPPolicy.parsedTrustedProxies)
					clientIP = clientIP_IP.String()
				} else {
					clientIP_IP, _ := utils.GetClientIPFromRequest(req, false, nil)
					clientIP = clientIP_IP.String()
				}
				t.Errorf("Expected status code %d, got %d. Client IP used: %s. XFF: '%s', XRealIP: '%s', RemoteAddr: '%s'",
					tt.expectedStatusCode, rr.Code, clientIP, tt.xForwardedFor, tt.xRealIP, tt.remoteAddr)
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

// testLogger returns a logger that logs to the test's t.Log.
