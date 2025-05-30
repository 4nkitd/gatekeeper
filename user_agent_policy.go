package gatekeeper

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

func newParsedUserAgentPolicy(config *UserAgentPolicyConfig) (*parsedUserAgentPolicy, error) {
	if config.Mode != ModeBlacklist && config.Mode != ModeWhitelist {
		return nil, fmt.Errorf("invalid UserAgentPolicy mode: %s", config.Mode)
	}

	parsed := &parsedUserAgentPolicy{
		config:           config,
		exactSet:         make(map[string]struct{}),
		compiledPatterns: make([]*regexp.Regexp, 0, len(config.Patterns)),
	}

	for _, ua := range config.Exact {
		if ua == "" {
			continue
		}
		parsed.exactSet[strings.ToLower(ua)] = struct{}{}
	}

	for _, pattern := range config.Patterns {
		if pattern == "" {
			continue
		}
		// Add (?i) for case-insensitivity if not already a complex pattern
		// A simple check: if it doesn't start with `(?` it's likely a simple pattern.
		// Users can provide their own flags if needed.
		// Forcing case-insensitivity might be too opinionated. Let's assume users know regex.
		// For User-Agents, case-insensitivity is often desired. Let's default to it for simplicity.
		// If the pattern already includes case flags, regex.Compile will handle it.
		// A common way to make a regex case-insensitive is to prefix with `(?i)`.
		// The user should specify `(?i)` in their pattern if they want case-insensitivity.
		// For `Exact` matches, we are doing ToLower. For patterns, let's leave it to the user.
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid User-Agent pattern '%s': %w", pattern, err)
		}
		parsed.compiledPatterns = append(parsed.compiledPatterns, re)
	}

	if len(parsed.exactSet) == 0 && len(parsed.compiledPatterns) == 0 {
		return nil, fmt.Errorf("UserAgentPolicy defined but no exact strings or patterns provided")
	}

	return parsed, nil
}

// UserAgentPolicy is a middleware that enforces User-Agent blacklisting/whitelisting.
func (gk *Gatekeeper) UserAgentPolicy(next http.Handler) http.Handler {
	if gk.parsedUserAgentPolicy == nil {
		return next // No policy configured
	}
	p := gk.parsedUserAgentPolicy // Local var for convenience

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgent := r.Header.Get("User-Agent")
		lowerUserAgent := strings.ToLower(userAgent) // For exact matches

		matched := false
		// Check exact matches first (faster)
		if _, ok := p.exactSet[lowerUserAgent]; ok {
			matched = true
		}

		// Check patterns if not already matched by exact string
		if !matched {
			for _, re := range p.compiledPatterns {
				if re.MatchString(userAgent) { // Patterns match against original case UA
					matched = true
					break
				}
			}
		}

		// Decision logic based on mode
		block := false
		reason := ""
		if p.config.Mode == ModeBlacklist {
			if matched {
				block = true
				reason = fmt.Sprintf("User-Agent '%s' is blacklisted", userAgent)
			}
		} else { // ModeWhitelist
			if !matched {
				block = true
				reason = fmt.Sprintf("User-Agent '%s' is not in whitelist", userAgent)
			}
		}

		if block {
			gk.blockRequest(w, r, gk.config.DefaultBlockStatusCode, gk.config.DefaultBlockMessage, reason)
			return
		}

		next.ServeHTTP(w, r)
	})
}
