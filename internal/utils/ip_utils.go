package utils

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// privateCIDRs is a list of IP ranges for private networks.
// Source: https://en.wikipedia.org/wiki/Private_network
var privateCIDRs = []string{
	"127.0.0.0/8",    // IPv4 loopback
	"10.0.0.0/8",     // RFC1918
	"172.16.0.0/12",  // RFC1918
	"192.168.0.0/16", // RFC1918
	"169.254.0.0/16", // RFC3927 link-local
	"::1/128",        // IPv6 loopback
	"fe80::/10",      // IPv6 link-local
	"fc00::/7",       // IPv6 unique local addr
}

var parsedPrivateCIDRs []*net.IPNet

func init() {
	parsedPrivateCIDRs = make([]*net.IPNet, len(privateCIDRs))
	for i, cidrStr := range privateCIDRs {
		_, cidrnet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			panic(fmt.Sprintf("ip_utils: failed to parse private CIDR %s: %v", cidrStr, err))
		}
		parsedPrivateCIDRs[i] = cidrnet
	}
}

func isPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, privateCIDR := range parsedPrivateCIDRs {
		if privateCIDR.Contains(ip) {
			return true
		}
	}
	return false
}

// GetClientIPFromRequest extracts the client's IP address from the request.
// It considers X-Forwarded-For and X-Real-IP headers if trustProxyHeaders is true
// and the direct connection comes from a trusted proxy.
func GetClientIPFromRequest(r *http.Request, trustProxyHeaders bool, trustedProxies []*net.IPNet) (net.IP, error) {
	remoteIPStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// If r.RemoteAddr is not in host:port format (e.g. Unix socket), handle it
		remoteIPStr = r.RemoteAddr
	}
	remoteIP := net.ParseIP(remoteIPStr)
	if remoteIP == nil {
		return nil, fmt.Errorf("invalid remote address: %s", r.RemoteAddr)
	}

	if !trustProxyHeaders {
		return remoteIP, nil
	}

	// Check if the direct connection (remoteIP) is from a trusted proxy
	isTrustedDirectConnection := false
	if len(trustedProxies) == 0 {
		// If trustedProxies is empty, trust any proxy (less secure)
		// Or, more securely, only trust if remoteIP is private, implying an internal proxy.
		// For now, let's assume if trustedProxies is empty, we don't trust XFF from public IPs.
		// If the user wants to trust all proxies, they should specify broad CIDRs like 0.0.0.0/0
		// This behavior might need refinement. A common approach is to trust XFF if remoteIP is private.
		if isPrivateIP(remoteIP) {
			isTrustedDirectConnection = true
		}
	} else {
		for _, trustedCIDR := range trustedProxies {
			if trustedCIDR.Contains(remoteIP) {
				isTrustedDirectConnection = true
				break
			}
		}
	}

	if !isTrustedDirectConnection {
		// If the direct connection is not from a trusted proxy, return the direct IP
		return remoteIP, nil
	}

	// If trusted, try to get IP from headers
	// X-Forwarded-For can be a comma-separated list of IPs. The first one is the original client.
	// e.g., X-Forwarded-For: client, proxy1, proxy2
	// We should take the *leftmost* non-private IP if proxies are stripping private IPs,
	// or simply the leftmost if our direct connection is trusted.
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		for _, ipStr := range ips {
			clientIP := net.ParseIP(strings.TrimSpace(ipStr))
			// Optional: if you want to ensure the IP from XFF is not a private IP
			// from an untrusted internal hop, you might add more checks here.
			// For now, we take the first valid IP.
			if clientIP != nil {
				return clientIP, nil
			}
		}
	}

	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		clientIP := net.ParseIP(strings.TrimSpace(realIP))
		if clientIP != nil {
			return clientIP, nil
		}
	}

	// If headers are not present or invalid, fall back to remoteIP (which is a trusted proxy)
	// This case implies the trusted proxy didn't set the headers, or set them incorrectly.
	// Returning remoteIP (the proxy's IP) is safer than returning nothing.
	return remoteIP, nil
}

// ParseIPsAndCIDRs parses slices of IP strings and CIDR strings.
func ParseIPsAndCIDRs(ipStrings []string, cidrStrings []string) (map[string]struct{}, []*net.IPNet, error) {
	parsedIPs := make(map[string]struct{})
	parsedCIDRs := make([]*net.IPNet, 0, len(cidrStrings))

	for _, ipStr := range ipStrings {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, nil, fmt.Errorf("invalid IP address string: %s", ipStr)
		}
		parsedIPs[ip.String()] = struct{}{} // Store canonical string form
	}

	for _, cidrStr := range cidrStrings {
		_, ipNet, err := net.ParseCIDR(cidrStr)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid CIDR string: %s: %w", cidrStr, err)
		}
		parsedCIDRs = append(parsedCIDRs, ipNet)
	}
	return parsedIPs, parsedCIDRs, nil
}
