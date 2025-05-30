# IP Policy Reference

The IP Policy provides comprehensive IP-based access control for your applications, supporting both IPv4 and IPv6 addresses, CIDR ranges, and proxy-aware client IP detection.

## 📋 Overview

The IP Policy can operate in two modes:
- **Blacklist Mode:** Block specific IPs/ranges (default allow)
- **Whitelist Mode:** Allow only specific IPs/ranges (default block)

## ⚙️ Configuration

### Basic Configuration

```go
ipPolicy := &gatekeeper.IPPolicyConfig{
    Mode: gatekeeper.ModeBlacklist, // or ModeWhitelist
    IPs:  []string{"192.168.1.100", "10.0.0.50"},
    CIDRs: []string{"192.168.1.0/24", "10.0.0.0/8"},
}
```

### JSON Configuration

```json
{
    "ipPolicy": {
        "mode": "BLACKLIST",
        "ips": ["192.168.1.100", "203.0.113.45"],
        "cidrs": ["192.168.1.0/24", "10.0.0.0/8"],
        "trustProxyHeaders": true,
        "trustedProxies": ["172.17.0.0/16"]
    }
}
```

## 🔧 Configuration Options

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `mode` | `PolicyMode` | Yes | - | `BLACKLIST` or `WHITELIST` |
| `ips` | `[]string` | No | `[]` | List of specific IP addresses |
| `cidrs` | `[]string` | No | `[]` | List of CIDR ranges |
| `trustProxyHeaders` | `bool` | No | `false` | Trust X-Forwarded-For headers |
| `trustedProxies` | `[]string` | No | `[]` | IPs/CIDRs of trusted proxies |

## 🎯 Mode Behaviors

### Blacklist Mode

```go
// Block specific IPs, allow everything else
ipPolicy := &gatekeeper.IPPolicyConfig{
    Mode: gatekeeper.ModeBlacklist,
    IPs:  []string{"192.168.1.100", "203.0.113.45"},
    CIDRs: []string{"10.0.0.0/8"},
}
```

**Behavior:**
- ✅ Allow: Any IP not in the block list
- ❌ Block: IPs in the `ips` list or matching `cidrs` ranges

### Whitelist Mode

```go
// Allow only specific IPs, block everything else
ipPolicy := &gatekeeper.IPPolicyConfig{
    Mode: gatekeeper.ModeWhitelist,
    IPs:  []string{"192.168.1.10", "192.168.1.20"},
    CIDRs: []string{"172.16.0.0/12"},
}
```

**Behavior:**
- ✅ Allow: Only IPs in the `ips` list or matching `cidrs` ranges
- ❌ Block: All other IPs

## 🌐 Proxy Support

### Basic Proxy Handling

When your application runs behind a proxy or load balancer:

```go
ipPolicy := &gatekeeper.IPPolicyConfig{
    Mode:              gatekeeper.ModeBlacklist,
    IPs:               []string{"203.0.113.45"},
    TrustProxyHeaders: true,
}
```

### Trusted Proxy Configuration

For enhanced security, specify which proxies to trust:

```go
ipPolicy := &gatekeeper.IPPolicyConfig{
    Mode:              gatekeeper.ModeBlacklist,
    IPs:               []string{"203.0.113.45"},
    TrustProxyHeaders: true,
    TrustedProxies:    []string{"172.17.0.0/16", "192.168.0.1"},
}
```

### Proxy Headers Checked

When `TrustProxyHeaders` is enabled, the following headers are checked in order:

1. `X-Forwarded-For` (first IP in chain)
2. `X-Real-IP`
3. `X-Client-IP`
4. `CF-Connecting-IP` (Cloudflare)
5. `True-Client-IP` (Akamai)
6. Remote address (fallback)

## 📝 IP Address Formats

### IPv4 Addresses

```json
{
    "ips": [
        "192.168.1.100",
        "203.0.113.45",
        "10.0.0.1"
    ]
}
```

### IPv6 Addresses

```json
{
    "ips": [
        "2001:db8::1",
        "::1",
        "fe80::1%lo0"
    ]
}
```

### CIDR Ranges

```json
{
    "cidrs": [
        "192.168.1.0/24",      // IPv4 subnet
        "10.0.0.0/8",          // Large IPv4 range
        "2001:db8::/32",       // IPv6 subnet
        "172.16.0.0/12"        // Private IP range
    ]
}
```

## 🏗️ Common Use Cases

### 1. Block Malicious IPs

```go
// Block known bad actors
config := &gatekeeper.Config{
    IPPolicy: &gatekeeper.IPPolicyConfig{
        Mode: gatekeeper.ModeBlacklist,
        IPs: []string{
            "203.0.113.45",    // Known bot
            "198.51.100.100",  // Malicious scanner
        },
        CIDRs: []string{
            "192.0.2.0/24",    // Suspicious network
        },
    },
}
```

### 2. Admin Panel Protection

```go
// Allow only office IPs to access admin routes
config := &gatekeeper.Config{
    IPPolicy: &gatekeeper.IPPolicyConfig{
        Mode: gatekeeper.ModeWhitelist,
        CIDRs: []string{
            "203.0.113.0/24",  // Office network
            "198.51.100.0/24", // VPN range
        },
        IPs: []string{
            "192.0.2.10",      // CEO's home IP
        },
    },
}
```

### 3. Load Balancer Setup

```go
// Behind AWS ALB or similar
config := &gatekeeper.Config{
    IPPolicy: &gatekeeper.IPPolicyConfig{
        Mode:              gatekeeper.ModeBlacklist,
        IPs:               []string{"203.0.113.45"},
        TrustProxyHeaders: true,
        TrustedProxies: []string{
            "172.31.0.0/16",   // AWS VPC default range
            "10.0.0.0/8",      // Internal load balancers
        },
    },
}
```

### 4. Cloudflare Integration

```go
// Trust Cloudflare proxy IPs
config := &gatekeeper.Config{
    IPPolicy: &gatekeeper.IPPolicyConfig{
        Mode:              gatekeeper.ModeBlacklist,
        IPs:               []string{"203.0.113.45"},
        TrustProxyHeaders: true,
        TrustedProxies: []string{
            // Cloudflare IPv4 ranges
            "173.245.48.0/20",
            "103.21.244.0/22",
            "103.22.200.0/22",
            "103.31.4.0/22",
            // Add more Cloudflare ranges as needed
        },
    },
}
```

## 🔒 Security Considerations

### 1. Proxy Header Validation

⚠️ **Important:** Only enable `TrustProxyHeaders` when you control the proxy layer.

```go
// ❌ DANGEROUS: Trusting headers without validation
ipPolicy := &gatekeeper.IPPolicyConfig{
    TrustProxyHeaders: true, // Anyone can spoof headers!
}

// ✅ SAFE: Trusting headers only from known proxies
ipPolicy := &gatekeeper.IPPolicyConfig{
    TrustProxyHeaders: true,
    TrustedProxies:    []string{"172.17.0.0/16"}, // Only trust Docker network
}
```

### 2. IPv6 Considerations

Ensure your blocklist includes both IPv4 and IPv6 versions:

```go
ipPolicy := &gatekeeper.IPPolicyConfig{
    Mode: gatekeeper.ModeBlacklist,
    IPs: []string{
        "203.0.113.45",    // IPv4
        "2001:db8::45",    // IPv6 equivalent
    },
}
```

### 3. Private IP Ranges

Be careful with private IP ranges in production:

```go
// Common private ranges
privateCIDRs := []string{
    "10.0.0.0/8",        // Class A private
    "172.16.0.0/12",     // Class B private
    "192.168.0.0/16",    // Class C private
    "127.0.0.0/8",       // Loopback
    "169.254.0.0/16",    // Link-local
}
```

## 📊 Performance

### Optimization Tips

1. **CIDR over Individual IPs:** Use CIDR ranges for better performance
   ```go
   // ✅ Better
   CIDRs: []string{"192.168.1.0/24"}
   
   // ❌ Less efficient
   IPs: []string{"192.168.1.1", "192.168.1.2", ..., "192.168.1.254"}
   ```

2. **Cache Parsed Networks:** The policy automatically caches parsed networks for better performance

3. **Whitelist Performance:** Whitelist mode with small allow lists performs better than blacklist mode with large block lists

### Memory Usage

- Each IP address: ~16 bytes
- Each CIDR range: ~32 bytes + parsed network data
- IPv6 addresses: Same memory usage as IPv4 (net.IP handles both efficiently)

## 🧪 Testing

### Unit Testing Your IP Policy

```go
func TestIPPolicy(t *testing.T) {
    policy := &gatekeeper.IPPolicyConfig{
        Mode: gatekeeper.ModeBlacklist,
        IPs:  []string{"192.168.1.100"},
        CIDRs: []string{"10.0.0.0/8"},
    }
    
    // Test blocked IP
    assert.True(t, policy.IsBlocked("192.168.1.100", nil))
    
    // Test blocked CIDR
    assert.True(t, policy.IsBlocked("10.0.0.50", nil))
    
    // Test allowed IP
    assert.False(t, policy.IsBlocked("203.0.113.45", nil))
}
```

### Integration Testing

```bash
# Test blocked IP
curl -H "X-Forwarded-For: 192.168.1.100" http://localhost:8080/
# Should return 403 Forbidden

# Test allowed IP
curl -H "X-Forwarded-For: 203.0.113.45" http://localhost:8080/
# Should return normal response
```

## 🔗 Related Documentation

- [Configuration Reference](configuration.md)
- [Framework Integration](../guides/framework-integration.md)
- [Security Best Practices](../guides/security-best-practices.md)
- [Proxy Setup Guide](../guides/proxy-setup.md)
