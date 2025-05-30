package gatekeeper

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// newParsedRefererPolicy creates a parsed referer policy from configuration
func newParsedRefererPolicy(config *RefererPolicyConfig) (*parsedRefererPolicy, error) {
	if config == nil {
		return nil, fmt.Errorf("referer policy config is nil")
	}

	parsed := &parsedRefererPolicy{
		config:   config,
		exactSet: make(map[string]struct{}),
	}

	// Process exact referers (case-insensitive)
	for _, referer := range config.Exact {
		parsed.exactSet[strings.ToLower(referer)] = struct{}{}
	}

	// Compile regex patterns
	for _, pattern := range config.Patterns {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid referer regex pattern '%s': %w", pattern, err)
		}
		parsed.compiledPatterns = append(parsed.compiledPatterns, compiled)
	}

	return parsed, nil
}

// RefererPolicy implements the referer-based access control middleware
func (gk *Gatekeeper) RefererPolicy(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		referer := r.Header.Get("Referer")

		// If no referer policy is configured, allow the request
		if gk.parsedRefererPolicy == nil {
			next.ServeHTTP(w, r)
			return
		}

		config := gk.parsedRefererPolicy.config
		isMatched := gk.isRefererMatched(referer)

		var shouldBlock bool
		var reason string

		switch config.Mode {
		case ModeBlacklist:
			if isMatched {
				shouldBlock = true
				reason = fmt.Sprintf("referer '%s' is blacklisted", referer)
			}
		case ModeWhitelist:
			if !isMatched {
				shouldBlock = true
				if referer == "" {
					reason = "no referer provided and whitelist mode is active"
				} else {
					reason = fmt.Sprintf("referer '%s' is not whitelisted", referer)
				}
			}
		default:
			gk.logger.Printf("Invalid referer policy mode: %s", config.Mode)
			next.ServeHTTP(w, r)
			return
		}

		if shouldBlock {
			gk.blockRequest(w, r, gk.config.DefaultBlockStatusCode, gk.config.DefaultBlockMessage, reason)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// isRefererMatched checks if the referer matches any configured pattern or exact string
func (gk *Gatekeeper) isRefererMatched(referer string) bool {
	if gk.parsedRefererPolicy == nil {
		return false
	}

	// Normalize referer for case-insensitive comparison
	refererLower := strings.ToLower(referer)

	// Check exact matches
	if _, exists := gk.parsedRefererPolicy.exactSet[refererLower]; exists {
		return true
	}

	// Check regex patterns
	for _, pattern := range gk.parsedRefererPolicy.compiledPatterns {
		if pattern.MatchString(referer) {
			return true
		}
	}

	return false
}
