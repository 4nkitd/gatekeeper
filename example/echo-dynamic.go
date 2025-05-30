package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/4nkitd/gatekeeper"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// Example demonstrating dynamic configuration with hot reloading
func main() {
	// Initialize Echo
	e := echo.New()

	// Add built-in middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Option 1: Using ConfigWatcher directly
	log.Println("🔧 Setting up dynamic configuration watcher...")

	// Create a config watcher with custom options
	watcher, err := gatekeeper.NewConfigWatcher("config.json", &gatekeeper.ConfigWatcherOptions{
		CheckInterval: 10 * time.Second, // Check every 10 seconds
		Logger:        log.New(os.Stdout, "[ConfigWatcher] ", log.LstdFlags),
		OnConfigReload: func(config *gatekeeper.Config, err error) {
			if err != nil {
				log.Printf("❌ Config reload failed: %v", err)
			} else {
				log.Printf("✅ Configuration successfully reloaded!")
				// You can add custom logic here when config reloads
			}
		},
	})
	if err != nil {
		log.Fatalf("Failed to create config watcher: %v", err)
	}

	// Start the watcher
	watcher.Start()
	defer watcher.Stop()

	// Use the dynamic middleware
	e.Use(gatekeeper.EchoMiddlewareFromConfigWatcher(watcher))

	// Option 2: One-step setup (alternative approach)
	/*
		middleware, watcher, err := gatekeeper.EchoMiddlewareFromConfigFile("config.json", &gatekeeper.ConfigWatcherOptions{
			CheckInterval: 10 * time.Second,
		})
		if err != nil {
			log.Fatalf("Failed to setup dynamic config: %v", err)
		}
		watcher.Start()
		defer watcher.Stop()
		e.Use(middleware)
	*/

	// Define routes
	e.GET("/", func(c echo.Context) error {
		return c.HTML(http.StatusOK, `
		<h1>🛡️ Gatekeeper Dynamic Configuration Demo</h1>
		<p>This server uses dynamic configuration that reloads automatically!</p>
		<h2>Test Configuration Changes:</h2>
		<ol>
			<li>Try accessing this page normally ✅</li>
			<li>Edit <code>config.json</code> to change security policies</li>
			<li>Wait 10 seconds for auto-reload</li>
			<li>Test the new configuration!</li>
		</ol>
		<h2>Test Endpoints:</h2>
		<ul>
			<li><a href="/health">GET /health</a> - Health check</li>
			<li><a href="/search?q=test">GET /search?q=test</a> - Search (profanity checked)</li>
			<li><a href="/admin">GET /admin</a> - Admin area</li>
			<li><a href="/config-info">GET /config-info</a> - Current config info</li>
		</ul>
		<h2>Try These Tests:</h2>
		<ul>
			<li>Search with profanity: <a href="/search?q=badword">/search?q=badword</a></li>
			<li>Rapid requests to test rate limiting</li>
			<li>Change User-Agent to test blocking</li>
		</ul>
		`)
	})

	e.GET("/health", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{
			"status":    "healthy",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	})

	e.GET("/search", func(c echo.Context) error {
		query := c.QueryParam("q")
		return c.JSON(http.StatusOK, map[string]interface{}{
			"query":   query,
			"results": []string{"Result 1", "Result 2", "Result 3"},
			"message": "Search completed successfully",
		})
	})

	e.POST("/api/submit", func(c echo.Context) error {
		message := c.FormValue("message")
		return c.JSON(http.StatusOK, map[string]interface{}{
			"message":   "Form submitted successfully",
			"received":  message,
			"timestamp": time.Now().Format(time.RFC3339),
		})
	})

	e.POST("/api/comment", func(c echo.Context) error {
		var comment struct {
			Text   string `json:"text"`
			Author string `json:"author"`
		}
		if err := c.Bind(&comment); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
		}
		return c.JSON(http.StatusOK, map[string]interface{}{
			"message":   "Comment posted successfully",
			"comment":   comment,
			"timestamp": time.Now().Format(time.RFC3339),
		})
	})

	e.GET("/admin", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{
			"message": "Welcome to admin area",
			"access":  "authorized",
		})
	})

	e.GET("/config-info", func(c echo.Context) error {
		gk := watcher.GetGatekeeper()
		// Note: In a real application, you might want to expose configuration
		// info in a more structured way or add authentication to this endpoint
		return c.JSON(http.StatusOK, map[string]interface{}{
			"message":        "Dynamic configuration active",
			"lastReload":     time.Now().Format(time.RFC3339),
			"checkInterval":  "10s",
			"configFile":     "config.json",
			"gatekeeperInfo": "Configuration loaded and active",
			"policies": map[string]bool{
				"ipPolicy":        gk != nil,
				"userAgentPolicy": gk != nil,
				"refererPolicy":   gk != nil,
				"rateLimiter":     gk != nil,
				"profanityFilter": gk != nil,
			},
		})
	})

	// Startup information
	log.Println("🛡️ Gatekeeper Dynamic Configuration Demo")
	log.Println("📁 Configuration file: config.json")
	log.Println("⏱️  Check interval: 10 seconds")
	log.Println("🔄 Hot reloading: enabled")
	log.Println("")
	log.Println("🌐 Server starting on http://localhost:8080")
	log.Println("📖 Try editing config.json while the server is running!")
	log.Println("📖 Watch the logs for automatic configuration reloads")

	e.Logger.Fatal(e.Start(":8080"))
}
