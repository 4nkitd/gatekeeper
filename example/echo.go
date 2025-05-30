package main

import (
	"net/http"
	"time"

	"github.com/4nkitd/gatekeeper"
	"github.com/4nkitd/gatekeeper/store"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// Note: The echoAdapter function is no longer needed!
// Gatekeeper now provides built-in Echo middleware support.

func main() {
	// Initialize Echo
	e := echo.New()

	// Configure Gatekeeper with comprehensive security policies
	config := gatekeeper.Config{
		// IP Policy - Block specific malicious IPs and allow only trusted networks
		IPPolicy: &gatekeeper.IPPolicyConfig{
			Mode:  gatekeeper.ModeBlacklist,
			IPs:   []string{"1.2.3.4", "5.6.7.8"}, // Block specific malicious IPs
			CIDRs: []string{"192.168.100.0/24"},   // Block entire suspicious subnet
			// Uncomment for proxy support:
			// TrustProxyHeaders: true,
			// TrustedProxies:    []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
		},

		// User-Agent Policy - Block known bots and scrapers
		UserAgentPolicy: &gatekeeper.UserAgentPolicyConfig{
			Mode: gatekeeper.ModeBlacklist,
			Exact: []string{
				"BadBot/1.0",
				"EvilScraper/2.0",
				"MaliciousBot",
			},
			Patterns: []string{
				`(?i)^.*bot.*scanner.*$`, // Block bot scanners (case-insensitive)
				`(?i)^.*scraper.*$`,      // Block scrapers
				`^curl/.*`,               // Block curl requests
				`^wget/.*`,               // Block wget requests
				`(?i)^.*sqlmap.*$`,       // Block SQL injection tools
				`(?i)^.*nikto.*$`,        // Block vulnerability scanners
			},
		},

		// Referer Policy - Control access based on HTTP Referer header
		RefererPolicy: &gatekeeper.RefererPolicyConfig{
			Mode: gatekeeper.ModeBlacklist,
			Exact: []string{
				"http://malicious-site.com",
				"https://spam-domain.net",
				"http://phishing-site.org",
			},
			Patterns: []string{
				`(?i).*evil\.com.*`,  // Block any referer containing evil.com
				`(?i).*phishing\..*`, // Block phishing domains
				`(?i).*malware\..*`,  // Block malware-related domains
				`^http://.*`,         // Block all non-HTTPS referers (force HTTPS)
			},
		},

		// Rate Limiter - Protect against DDoS and brute force attacks
		RateLimiter: &gatekeeper.RateLimiterConfig{
			Requests: 60, // 60 requests per minute per IP
			Period:   1 * time.Minute,
			Store:    store.NewMemoryStore(5 * time.Minute), // Clean up after 5 minutes
			Exceptions: &gatekeeper.RateLimiterExceptions{
				IPWhitelist: []string{
					"127.0.0.1",  // Localhost
					"::1",        // IPv6 localhost
					"10.0.0.0/8", // Private networks (if trusted)
				},
				RouteWhitelistPatterns: []string{
					`^/health$`,   // Health check endpoint
					`^/metrics$`,  // Metrics endpoint
					`^/static/.*`, // Static assets
				},
			},
			LimitExceededMessage:    "Rate limit exceeded. Please slow down!",
			LimitExceededStatusCode: http.StatusTooManyRequests,
		},

		// Profanity Filter - Content moderation for user inputs
		ProfanityFilter: &gatekeeper.ProfanityFilterConfig{
			BlockWords: []string{
				"badword",
				"spam",
				"offensive",
				"inappropriate",
				"malicious",
			},
			AllowWords: []string{
				"scunthorpe", // Classic example of false positive
				"assess",     // Contains "ass" but is legitimate
			},
			CheckQueryParams:  true, // Check URL parameters
			CheckFormFields:   true, // Check form submissions
			CheckJSONBody:     true, // Check JSON payloads
			BlockedMessage:    "Content contains inappropriate language",
			BlockedStatusCode: http.StatusBadRequest,
		},

		// Global settings
		DefaultBlockStatusCode: http.StatusForbidden,
		DefaultBlockMessage:    "Access denied by security policy",
	}

	// Apply Gatekeeper middleware - Method 1: Create instance then get middleware
	gk, err := gatekeeper.New(config)
	if err != nil {
		e.Logger.Fatal("Failed to initialize Gatekeeper: ", err)
	}
	e.Use(gk.EchoMiddleware())

	// Alternative Method 2: One-step creation (commented out)
	// gkMiddleware, err := gatekeeper.EchoMiddlewareFromConfig(config)
	// if err != nil {
	//     e.Logger.Fatal("Failed to initialize Gatekeeper: ", err)
	// }
	// e.Use(gkMiddleware)

	// Add Echo's built-in middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	// Define routes with different protection levels

	// Public routes (still protected by gatekeeper)
	e.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"message": "Welcome! You've passed all security checks.",
			"ip":      c.RealIP(),
			"agent":   c.Request().UserAgent(),
		})
	})

	// Health check endpoint (rate limit exempt)
	e.GET("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{
			"status": "healthy",
			"time":   time.Now().Format(time.RFC3339),
		})
	})

	// API endpoint that accepts form data (profanity filtered)
	e.POST("/api/submit", func(c echo.Context) error {
		data := make(map[string]interface{})

		// Get form data
		name := c.FormValue("name")
		message := c.FormValue("message")

		data["received"] = map[string]string{
			"name":    name,
			"message": message,
		}
		data["status"] = "Content approved and processed"

		return c.JSON(http.StatusOK, data)
	})

	// API endpoint that accepts JSON (profanity filtered)
	e.POST("/api/comment", func(c echo.Context) error {
		var comment struct {
			Author  string `json:"author"`
			Content string `json:"content"`
			Email   string `json:"email"`
		}

		if err := c.Bind(&comment); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{
				"error": "Invalid JSON format",
			})
		}

		return c.JSON(http.StatusOK, map[string]interface{}{
			"message": "Comment accepted",
			"comment": comment,
			"id":      time.Now().Unix(),
		})
	})

	// Protected admin endpoint (all policies apply)
	e.GET("/admin", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"message": "Admin area accessed successfully",
			"policies": map[string]bool{
				"ip_policy_active":         config.IPPolicy != nil,
				"user_agent_policy_active": config.UserAgentPolicy != nil,
				"referer_policy_active":    config.RefererPolicy != nil,
				"rate_limiter_active":      config.RateLimiter != nil,
				"profanity_filter_active":  config.ProfanityFilter != nil,
			},
		})
	})

	// Static file serving (rate limit exempt)
	e.Static("/static", "static")

	// Demo endpoint to test profanity filter with query params
	e.GET("/search", func(c echo.Context) error {
		query := c.QueryParam("q")
		category := c.QueryParam("category")

		return c.JSON(http.StatusOK, map[string]interface{}{
			"search_query": query,
			"category":     category,
			"results":      []string{"Result 1", "Result 2", "Result 3"},
			"message":      "Search completed successfully",
		})
	})

	// Demonstration endpoint showing all security headers
	e.GET("/security-info", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"client_ip":    c.RealIP(),
			"user_agent":   c.Request().UserAgent(),
			"method":       c.Request().Method,
			"path":         c.Request().URL.Path,
			"query_params": c.Request().URL.Query(),
			"headers": map[string]string{
				"X-Forwarded-For": c.Request().Header.Get("X-Forwarded-For"),
				"X-Real-IP":       c.Request().Header.Get("X-Real-IP"),
				"Content-Type":    c.Request().Header.Get("Content-Type"),
			},
			"security_policies": map[string]interface{}{
				"gatekeeper_active": true,
				"policies": map[string]bool{
					"ip_filtering":         config.IPPolicy != nil,
					"user_agent_filtering": config.UserAgentPolicy != nil,
					"referer_filtering":    config.RefererPolicy != nil,
					"rate_limiting":        config.RateLimiter != nil,
					"profanity_filter":     config.ProfanityFilter != nil,
				},
			},
		})
	})

	// Start server
	e.Logger.Info("🚀 Starting Echo server with Gatekeeper protection...")
	e.Logger.Info("📊 Active policies:")
	if config.IPPolicy != nil {
		e.Logger.Info("  ✅ IP Policy (Blacklist mode)")
	}
	if config.UserAgentPolicy != nil {
		e.Logger.Info("  ✅ User-Agent Policy (Blacklist mode)")
	}
	if config.RefererPolicy != nil {
		e.Logger.Info("  ✅ Referer Policy (Blacklist mode)")
	}
	if config.RateLimiter != nil {
		e.Logger.Info("  ✅ Rate Limiter (60 requests/minute)")
	}
	if config.ProfanityFilter != nil {
		e.Logger.Info("  ✅ Profanity Filter")
	}

	e.Logger.Info("🌐 Server listening on http://localhost:8080")
	e.Logger.Info("📖 Try these endpoints:")
	e.Logger.Info("  GET  / - Welcome page")
	e.Logger.Info("  GET  /health - Health check")
	e.Logger.Info("  POST /api/submit - Form submission (try with 'message=badword')")
	e.Logger.Info("  POST /api/comment - JSON submission (try with profanity)")
	e.Logger.Info("  GET  /search?q=badword - Search with profanity check")
	e.Logger.Info("  GET  /admin - Admin area")
	e.Logger.Info("  GET  /security-info - Security information")

	e.Logger.Fatal(e.Start(":8080"))
}
