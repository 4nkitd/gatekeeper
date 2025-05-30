package gatekeeper

import (
	"fmt"
	"net"
	"net/http"
	"strconv"

	"github.com/4nkitd/gatekeeper/internal/utils" // Adjust import path
)

func (gk *Gatekeeper) RateLimit(next http.Handler) http.Handler {
	if gk.config.RateLimiter == nil || gk.config.RateLimiter.Store == nil {
		return next
	}
	rlc := gk.config.RateLimiter

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var clientIPForRateLimit net.IP
		var clientKeyForStore string

		// Try to get the reliable client IP
		parsedClientIP, err := utils.GetClientIPFromRequest(r,
			gk.config.IPPolicy != nil && gk.config.IPPolicy.TrustProxyHeaders,
			gk.parsedTrustedProxiesIfAvailable())

		if err == nil && parsedClientIP != nil {
			clientIPForRateLimit = parsedClientIP
			clientKeyForStore = parsedClientIP.String()
		} else {
			if err != nil {
				gk.logger.Printf("RateLimit: Error getting client IP: %v. Using RemoteAddr as fallback.", err)
			} else {
				gk.logger.Printf("RateLimit: GetClientIPFromRequest returned nil IP. Using RemoteAddr as fallback.")
			}
			// Fallback to r.RemoteAddr (less ideal but provides a key)
			ipStr, _, splitErr := net.SplitHostPort(r.RemoteAddr)
			if splitErr != nil {
				ipStr = r.RemoteAddr // For non "host:port" RemoteAddr like Unix sockets
			}
			clientKeyForStore = ipStr                 // Use string directly for store
			clientIPForRateLimit = net.ParseIP(ipStr) // Attempt to parse for exemption check
		}

		// Check exemptions if we have a valid net.IP for it
		if clientIPForRateLimit != nil && gk.isRateLimitExempt(r, clientIPForRateLimit) {
			next.ServeHTTP(w, r)
			return
		}
		// If clientIPForRateLimit was nil (e.g. from Unix socket that didn't parse to IP),
		// exemption check based on IP won't work, but route exemption might.
		// This logic can be refined if route-only exemptions are needed without a valid IP.
		// For now, if clientIPForRateLimit is nil, IP exemption check is skipped.

		allowed, retryAfter, storeErr := rlc.Store.Allow(clientKeyForStore, rlc.Requests, rlc.Period)
		if storeErr != nil {
			gk.logger.Printf("Rate limiter store error for key %s: %v", clientKeyForStore, storeErr)
			next.ServeHTTP(w, r) // Fail open
			return
		}

		if !allowed {
			w.Header().Set("Retry-After", strconv.FormatInt(int64(retryAfter.Seconds()), 10))
			gk.blockRequest(w, r, rlc.LimitExceededStatusCode, rlc.LimitExceededMessage, fmt.Sprintf("Rate limit exceeded for key %s", clientKeyForStore))
			return
		}

		next.ServeHTTP(w, r)
	})
}
