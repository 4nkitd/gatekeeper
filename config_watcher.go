package gatekeeper

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sync"
	"time"
)

// ConfigWatcher monitors a JSON configuration file and updates the Gatekeeper instance
// when the file changes.
type ConfigWatcher struct {
	filePath       string
	checkInterval  time.Duration
	gatekeeper     *Gatekeeper
	mu             sync.RWMutex
	stopChan       chan struct{}
	logger         *log.Logger
	onConfigReload func(*Config, error) // Optional callback for config reload events
	lastModTime    time.Time
	running        bool
}

// ConfigWatcherOptions provides configuration options for the ConfigWatcher
type ConfigWatcherOptions struct {
	CheckInterval  time.Duration        // How often to check the file (default: 30s)
	Logger         *log.Logger          // Logger for watcher events (default: standard log)
	OnConfigReload func(*Config, error) // Optional callback when config reloads
}

// NewConfigWatcher creates a new configuration file watcher
func NewConfigWatcher(filePath string, options *ConfigWatcherOptions) (*ConfigWatcher, error) {
	if options == nil {
		options = &ConfigWatcherOptions{}
	}

	// Set defaults
	if options.CheckInterval == 0 {
		options.CheckInterval = 30 * time.Second
	}
	if options.Logger == nil {
		options.Logger = log.New(os.Stdout, "[ConfigWatcher] ", log.LstdFlags)
	}

	// Initial config load
	config, err := loadConfigFromFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to load initial config: %w", err)
	}

	// Create gatekeeper instance
	gatekeeper, err := New(*config)
	if err != nil {
		return nil, fmt.Errorf("failed to create gatekeeper with initial config: %w", err)
	}

	// Get initial file modification time
	stat, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat config file: %w", err)
	}

	watcher := &ConfigWatcher{
		filePath:       filePath,
		checkInterval:  options.CheckInterval,
		gatekeeper:     gatekeeper,
		stopChan:       make(chan struct{}),
		logger:         options.Logger,
		onConfigReload: options.OnConfigReload,
		lastModTime:    stat.ModTime(),
		running:        false,
	}

	watcher.logger.Printf("ConfigWatcher initialized for file: %s", filePath)
	return watcher, nil
}

// Start begins monitoring the configuration file for changes
func (cw *ConfigWatcher) Start() {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	if cw.running {
		cw.logger.Printf("ConfigWatcher is already running")
		return
	}

	cw.running = true
	cw.logger.Printf("Starting ConfigWatcher with %v check interval", cw.checkInterval)

	go cw.watchLoop()
}

// Stop stops monitoring the configuration file
func (cw *ConfigWatcher) Stop() {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	if !cw.running {
		return
	}

	cw.running = false
	close(cw.stopChan)
	cw.logger.Printf("ConfigWatcher stopped")
}

// GetGatekeeper returns the current Gatekeeper instance (thread-safe)
func (cw *ConfigWatcher) GetGatekeeper() *Gatekeeper {
	cw.mu.RLock()
	defer cw.mu.RUnlock()
	return cw.gatekeeper
}

// watchLoop is the main monitoring loop
func (cw *ConfigWatcher) watchLoop() {
	ticker := time.NewTicker(cw.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cw.checkForConfigChanges()
		case <-cw.stopChan:
			return
		}
	}
}

// checkForConfigChanges checks if the config file has been modified and reloads if necessary
func (cw *ConfigWatcher) checkForConfigChanges() {
	stat, err := os.Stat(cw.filePath)
	if err != nil {
		cw.logger.Printf("Error checking config file: %v", err)
		if cw.onConfigReload != nil {
			cw.onConfigReload(nil, err)
		}
		return
	}

	// Check if file has been modified
	if stat.ModTime().After(cw.lastModTime) {
		cw.logger.Printf("Config file modified, reloading...")
		cw.reloadConfig()
		cw.lastModTime = stat.ModTime()
	}
}

// reloadConfig loads the new configuration and updates the Gatekeeper instance
func (cw *ConfigWatcher) reloadConfig() {
	// Load new config
	config, err := loadConfigFromFile(cw.filePath)
	if err != nil {
		cw.logger.Printf("Failed to load new config: %v", err)
		if cw.onConfigReload != nil {
			cw.onConfigReload(nil, err)
		}
		return
	}

	// Create new gatekeeper instance
	newGatekeeper, err := New(*config)
	if err != nil {
		cw.logger.Printf("Failed to create new gatekeeper instance: %v", err)
		if cw.onConfigReload != nil {
			cw.onConfigReload(config, err)
		}
		return
	}

	// Atomically replace the gatekeeper instance
	cw.mu.Lock()
	cw.gatekeeper = newGatekeeper
	cw.mu.Unlock()

	cw.logger.Printf("Configuration successfully reloaded")
	if cw.onConfigReload != nil {
		cw.onConfigReload(config, nil)
	}
}

// loadConfigFromFile loads and parses a JSON configuration file
func loadConfigFromFile(filePath string) (*Config, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse JSON config: %w", err)
	}

	return &config, nil
}

// NewGatekeeperFromFile creates a Gatekeeper instance from a JSON configuration file
// This is a convenience function for one-time config loading without watching.
func NewGatekeeperFromFile(filePath string) (*Gatekeeper, error) {
	config, err := loadConfigFromFile(filePath)
	if err != nil {
		return nil, err
	}

	return New(*config)
}

// NewGatekeeperWithWatcher creates both a ConfigWatcher and returns the initial Gatekeeper.
// This is useful when you want to start with a file-based config and enable hot reloading.
func NewGatekeeperWithWatcher(filePath string, options *ConfigWatcherOptions) (*Gatekeeper, *ConfigWatcher, error) {
	watcher, err := NewConfigWatcher(filePath, options)
	if err != nil {
		return nil, nil, err
	}

	return watcher.GetGatekeeper(), watcher, nil
}
