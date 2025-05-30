package gatekeeper

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/4nkitd/gatekeeper/store"
)

func TestRateLimiter(t *testing.T) {
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	tests := []struct {
		name                    string
		config                  RateLimiterConfig
		requests                int
		periodBetweenRequests   time.Duration
		expectedFinalStatusCode int
		expectedOKResponses     int
		clientIP                string
	}{
		{
			name: "Allow within limit",
			config: RateLimiterConfig{
				Requests: 2,
				Period:   1 * time.Second,
				Store:    store.NewMemoryStore(1 * time.Minute),
			},
			requests:                2,
			periodBetweenRequests:   100 * time.Millisecond,
			expectedFinalStatusCode: http.StatusOK,
			expectedOKResponses:     2,
			clientIP:                "1.2.3.4",
		},
		{
			name: "Block when exceeding limit",
			config: RateLimiterConfig{
				Requests: 1,
				Period:   1 * time.Second,
				Store:    store.NewMemoryStore(1 * time.Minute),
			},
			requests:                2,
			periodBetweenRequests:   100 * time.Millisecond,
			expectedFinalStatusCode: http.StatusTooManyRequests,
			expectedOKResponses:     1,
			clientIP:                "1.2.3.5",
		},
		{
			name: "Limit resets after period",
			config: RateLimiterConfig{
				Requests: 1,
				Period:   200 * time.Millisecond,
				Store:    store.NewMemoryStore(1 * time.Minute),
			},
			requests:                2,
			periodBetweenRequests:   300 * time.Millisecond, // First request, wait > period, second request
			expectedFinalStatusCode: http.StatusOK,
			expectedOKResponses:     2,
			clientIP:                "1.2.3.6",
		},
		{
			name: "IP Whitelist bypasses limit",
			config: RateLimiterConfig{
				Requests: 1,
				Period:   1 * time.Second,
				Store:    store.NewMemoryStore(1 * time.Minute),
				Exceptions: &RateLimiterExceptions{
					IPWhitelist: []string{"1.2.3.7"},
				},
			},
			requests:                3,
			periodBetweenRequests:   10 * time.Millisecond,
			expectedFinalStatusCode: http.StatusOK,
			expectedOKResponses:     3,
			clientIP:                "1.2.3.7",
		},
		{
			name: "Different IPs have different counters",
			config: RateLimiterConfig{
				Requests: 1,
				Period:   1 * time.Second,
				Store:    store.NewMemoryStore(1 * time.Minute),
			},
			requests:                0, // Mark to skip in the main loop
			expectedFinalStatusCode: 0,
			expectedOKResponses:     0,
		},
		{
			name: "Route Whitelist bypasses limit",
			config: RateLimiterConfig{
				Requests: 1,
				Period:   1 * time.Second,
				Store:    store.NewMemoryStore(1 * time.Minute),
				Exceptions: &RateLimiterExceptions{
					RouteWhitelistPatterns: []string{"^/public/.*"},
				},
			},
			requests:                0, // Mark to skip
			expectedFinalStatusCode: 0,
			expectedOKResponses:     0,
		},
	}

	for _, tt := range tests {
		if tt.requests == 0 { // Skip specially handled tests
			continue
		}
		t.Run(tt.name, func(t *testing.T) {
			if tt.config.Store == nil {
				tt.config.Store = store.NewMemoryStore(1 * time.Minute)
			}

			gk := &Gatekeeper{
				config: Config{
					RateLimiter:            &tt.config,
					DefaultBlockStatusCode: http.StatusForbidden,
				},
				logger: testLogger(t),
			}

			initializedGk, err := New(gk.config)
			if err != nil {
				t.Fatalf("Gatekeeper.New failed: %v", err)
			}
			if initializedGk.config.RateLimiter == nil {
				t.Fatalf("RateLimiter is nil after New()")
			}

			handlerToTest := initializedGk.RateLimit(dummyHandler)
			var finalStatusCode int
			okResponses := 0

			for i := 0; i < tt.requests; i++ {
				req := httptest.NewRequest("GET", "/", nil)
				req.RemoteAddr = tt.clientIP + ":12345" // Simulate client IP

				rr := httptest.NewRecorder()
				handlerToTest.ServeHTTP(rr, req)
				finalStatusCode = rr.Code

				if rr.Code == http.StatusOK {
					okResponses++
				}
				if i < tt.requests-1 && tt.periodBetweenRequests > 0 {
					time.Sleep(tt.periodBetweenRequests)
				}
			}

			if finalStatusCode != tt.expectedFinalStatusCode {
				t.Errorf("Expected final status code %d, got %d", tt.expectedFinalStatusCode, finalStatusCode)
			}
			if okResponses != tt.expectedOKResponses {
				t.Errorf("Expected %d OK responses, got %d", tt.expectedOKResponses, okResponses)
			}

			if c, ok := tt.config.Store.(interface{ Cleanup() }); ok {
				c.Cleanup()
			}
		})
	}

	t.Run("Different IPs have different counters", func(t *testing.T) {
		cfg := RateLimiterConfig{
			Requests: 1,
			Period:   10 * time.Second,
			Store:    store.NewMemoryStore(1 * time.Minute),
		}

		gkInstance, err := New(Config{RateLimiter: &cfg, Logger: testLogger(t)})
		if err != nil {
			t.Fatalf("Gatekeeper.New for 'Different IPs' test failed: %v", err)
		}
		handler := gkInstance.RateLimit(dummyHandler)

		req1 := httptest.NewRequest("GET", "/", nil)
		req1.RemoteAddr = "10.0.0.1:12345"
		rr1 := httptest.NewRecorder()
		handler.ServeHTTP(rr1, req1)
		if rr1.Code != http.StatusOK {
			t.Errorf("IP1: Expected status %d, got %d", http.StatusOK, rr1.Code)
		}

		req2 := httptest.NewRequest("GET", "/", nil)
		req2.RemoteAddr = "10.0.0.2:12345"
		rr2 := httptest.NewRecorder()
		handler.ServeHTTP(rr2, req2)
		if rr2.Code != http.StatusOK {
			t.Errorf("IP2: Expected status %d, got %d", http.StatusOK, rr2.Code)
		}

		rr1Again := httptest.NewRecorder()
		handler.ServeHTTP(rr1Again, req1)
		if rr1Again.Code != http.StatusTooManyRequests {
			t.Errorf("IP1 again: Expected status %d, got %d", http.StatusTooManyRequests, rr1Again.Code)
		}

		rr2Again := httptest.NewRecorder()
		handler.ServeHTTP(rr2Again, req2)
		if rr2Again.Code != http.StatusTooManyRequests {
			t.Errorf("IP2 again: Expected status %d, got %d", http.StatusTooManyRequests, rr2Again.Code)
		}
		if c, ok := cfg.Store.(interface{ Cleanup() }); ok {
			c.Cleanup()
		}
	})

	t.Run("Route Whitelist bypasses limit", func(t *testing.T) {
		cfg := RateLimiterConfig{
			Requests: 1,
			Period:   10 * time.Second,
			Store:    store.NewMemoryStore(1 * time.Minute),
			Exceptions: &RateLimiterExceptions{
				RouteWhitelistPatterns: []string{"^/public/.*"},
			},
		}

		gkInstance, err := New(Config{RateLimiter: &cfg, Logger: testLogger(t)})
		if err != nil {
			t.Fatalf("Gatekeeper.New for 'Route Whitelist' test failed: %v", err)
		}
		handler := gkInstance.RateLimit(dummyHandler)

		clientIP := "20.0.0.1:12345"

		reqPublic := httptest.NewRequest("GET", "/public/resource", nil)
		reqPublic.RemoteAddr = clientIP
		for i := 0; i < 3; i++ {
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, reqPublic)
			if rr.Code != http.StatusOK {
				t.Errorf("Public route (attempt %d): Expected status %d, got %d", i+1, http.StatusOK, rr.Code)
			}
		}

		reqPrivate := httptest.NewRequest("GET", "/private/resource", nil)
		reqPrivate.RemoteAddr = clientIP

		rrPrivate1 := httptest.NewRecorder()
		handler.ServeHTTP(rrPrivate1, reqPrivate)
		if rrPrivate1.Code != http.StatusOK {
			t.Errorf("Private route (attempt 1): Expected status %d, got %d", http.StatusOK, rrPrivate1.Code)
		}

		rrPrivate2 := httptest.NewRecorder()
		handler.ServeHTTP(rrPrivate2, reqPrivate)
		if rrPrivate2.Code != http.StatusTooManyRequests {
			t.Errorf("Private route (attempt 2): Expected status %d, got %d", http.StatusTooManyRequests, rrPrivate2.Code)
		}
		if c, ok := cfg.Store.(interface{ Cleanup() }); ok {
			c.Cleanup()
		}
	})

	t.Run("Concurrent requests from same IP", func(t *testing.T) {
		cfg := RateLimiterConfig{
			Requests: 5,
			Period:   1 * time.Second,
			Store:    store.NewMemoryStore(1 * time.Minute),
		}

		gkInstance, err := New(Config{RateLimiter: &cfg, Logger: testLogger(t)})
		if err != nil {
			t.Fatalf("Gatekeeper.New for 'Concurrent requests' test failed: %v", err)
		}
		handler := gkInstance.RateLimit(dummyHandler)

		numRequests := 10
		var wg sync.WaitGroup
		wg.Add(numRequests)

		successCount := 0
		var mu sync.Mutex

		clientIP := "30.0.0.1:12345"

		for i := 0; i < numRequests; i++ {
			go func() {
				defer wg.Done()
				req := httptest.NewRequest("GET", "/", nil)
				req.RemoteAddr = clientIP
				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, req)
				if rr.Code == http.StatusOK {
					mu.Lock()
					successCount++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()

		if successCount != int(cfg.Requests) {
			t.Errorf("Expected %d successful requests, got %d", cfg.Requests, successCount)
		}
		if c, ok := cfg.Store.(interface{ Cleanup() }); ok {
			c.Cleanup()
		}
	})

}
