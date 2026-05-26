package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/4nkitd/gatekeeper"
	"github.com/labstack/echo/v4"
)

func main() {
	// Initialize Echo
	e := echo.New()
	e.HideBanner = true

	// Create config watcher
	watcher, err := gatekeeper.NewConfigWatcher("config-test.json", &gatekeeper.ConfigWatcherOptions{
		CheckInterval: 5 * time.Second,
		Logger:        log.New(os.Stdout, "[ConfigWatcher] ", log.LstdFlags),
		OnConfigReload: func(config *gatekeeper.Config, err error) {
			if err != nil {
				log.Printf("❌ Config reload failed: %v", err)
			} else {
				log.Printf("✅ Configuration successfully reloaded!")
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

	// Simple test endpoints
	e.GET("/", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{
			"message":   "Config watcher test successful!",
			"timestamp": time.Now().Format(time.RFC3339),
		})
	})

	e.GET("/test", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"status":  "ok",
			"message": "Dynamic configuration is working",
			"query":   c.QueryParam("q"),
		})
	})

	log.Println("🛡️ Gatekeeper Config Watcher Test")
	log.Println("📁 Configuration file: config-test.json")
	log.Println("⏱️  Check interval: 5 seconds")
	log.Println("🌐 Server: http://localhost:8080")

	// Start server
	e.Logger.Fatal(e.Start(":8080"))
}
