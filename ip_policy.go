package gatekeeper

import (
	"fmt"
	"net"
	"net/http"

	"github.com/4nkitd/gatekeeper/internal/utils"
)

func newParsedIPPolicy(config *IPPolicyConfig) (*parsedIPPolicy, error) {
	if config.Mode != ModeBlacklist && config.Mode != ModeWhitelist {
		return nil, fmt.Errorf("invalid IPPolicy mode: %s", config.Mode)
	}

	parsed := &parsedIPPolicy{
		config: config,
	}

	var err error
	parsed.parsedIPs, parsed.parsedCIDRs, err = utils.ParseIPsAndCIDRs(config.IPs, config.CIDRs)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IPs/CIDRs: %w", err)
	}

	if config.TrustProxyHeaders {
		_, parsedTrustedProxiesSlice, err := utils.ParseIPsAndCIDRs(nil, config.TrustedProxies) // TrustedProxies are only CIDRs for simplicity now
		if err != nil {
			return nil, fmt.Errorf("failed to parse TrustedProxies CIDRs: %w", err)
		}
		parsed.parsedTrustedProxies = parsedTrustedProxiesSlice
	}

	if len(parsed.parsedIPs) == 0 && len(parsed.parsedCIDRs) == 0 {
		return nil, fmt.Errorf("IPPolicy defined but no IPs or CIDRs provided")
	}
	return parsed, nil
}

// IPPolicy is a middleware that enforces IP blacklisting/whitelisting.
func (gk *Gatekeeper) IPPolicy(next http.Handler) http.Handler {
	if gk.parsedIPPolicy == nil {
		return next // No policy configured
	}
	p := gk.parsedIPPolicy

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIPNet, err := utils.GetClientIPFromRequest(r, p.config.TrustProxyHeaders, p.parsedTrustedProxies)
		if err != nil {
			gk.logger.Printf("Error getting client IP: %v. RemoteAddr: %s", err, r.RemoteAddr)
			// Decide how to handle: block, or proceed with r.RemoteAddr?
			// For security, if IP cannot be determined reliably, it might be best to block
			// or log and allow depending on strictness. Let's block for now.
			gk.blockRequest(w, r, http.StatusInternalServerError, "Internal Server Error", "Could not determine client IP")
			return
		}
		clientIPStr := clientIPNet.String()

		matched := false
		// Check exact IP matches
		if _, ok := p.parsedIPs[clientIPStr]; ok {
			matched = true
		}

		// Check CIDR matches if not already matched
		if !matched {
			for _, cidr := range p.parsedCIDRs {
				if cidr.Contains(clientIPNet) {
					matched = true
					break
				}
			}
		}

		block := false
		reason := ""
		if p.config.Mode == ModeBlacklist {
			if matched {
				block = true
				reason = fmt.Sprintf("IP %s is blacklisted", clientIPStr)
			}
		} else { // ModeWhitelist
			if !matched {
				block = true
				reason = fmt.Sprintf("IP %s is not in whitelist", clientIPStr)
			}
		}

		if block {
			gk.blockRequest(w, r, gk.config.DefaultBlockStatusCode, gk.config.DefaultBlockMessage, reason)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// This replaces the placeholder in gatekeeper.go
func GetClientIP(r *http.Request, ipPolicy *parsedIPPolicy) string {
	if ipPolicy == nil { // Should not happen if IPPolicy middleware is active
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		return ip
	}
	ip, err := utils.GetClientIPFromRequest(r, ipPolicy.config.TrustProxyHeaders, ipPolicy.parsedTrustedProxies)
	if err != nil {
		// log error, return r.RemoteAddr as fallback?
		pip, _, _ := net.SplitHostPort(r.RemoteAddr)
		return pip
	}
	return ip.String()
}
