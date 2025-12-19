package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	consolemenu "github.com/letgo/console-menu"
	"github.com/letgo/cracker"
	networkmapper "github.com/letgo/network-mapper"
	"github.com/letgo/paths"
)

// dataDir is initialized at runtime to ensure proper path detection
var dataDir string

func init() {
	dataDir = paths.GetDataDir()
}

// List of required .txt files
var requiredTxtFiles = []string{
	"users.txt",
	"passwords.txt",
	"cURL-Bruteforce.txt",
	"valid-url.txt",
	"results.txt",
	"user-agent.txt",
}

// List of required proxy files
var requiredProxyFiles = []string{
	"proxy/raw-proxy.txt",
	"proxy/proxy.txt",
}

// Ensure all required .txt files exist, create if missing
func ensureTxtFilesExist() {
	// Create data directory if it doesn't exist
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		fmt.Printf("Error creating data directory: %v\n", err)
		return
	}

	for _, file := range requiredTxtFiles {
		filePath := filepath.Join(dataDir, file)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			f, err := os.Create(filePath)
			if err != nil {
				fmt.Printf("Error creating %s: %v\n", filePath, err)
			} else {
				f.Close()
				fmt.Printf("Created missing file: %s\n", filePath)
			}
		}
	}

	// Create proxy directory if it doesn't exist
	proxyDir := filepath.Join(dataDir, "proxy")
	if _, err := os.Stat(proxyDir); os.IsNotExist(err) {
		if err := os.MkdirAll(proxyDir, 0755); err != nil {
			fmt.Printf("Error creating proxy directory: %v\n", err)
		} else {
			fmt.Println("Created proxy directory")
		}
	}

	// Create required proxy files
	for _, file := range requiredProxyFiles {
		filePath := filepath.Join(dataDir, file)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			f, err := os.Create(filePath)
			if err != nil {
				fmt.Printf("Error creating %s: %v\n", filePath, err)
			} else {
				f.Close()
				fmt.Printf("Created missing file: %s\n", filePath)
			}
		}
	}
}

// Ensure network-mapper directories and configuration files exist
func ensureNetworkMapperExists() {
	configManager := networkmapper.NewConfigManager()

	// Create all required directories
	if err := configManager.EnsureDirectories(); err != nil {
		fmt.Printf("Error creating network-mapper directories: %v\n", err)
		return
	}

	// Initialize default configuration files
	if err := configManager.InitializeDefaultFiles(); err != nil {
		fmt.Printf("Error creating network-mapper configuration files: %v\n", err)
		return
	}

	// Check what was created and inform user
	networkMapperDir := configManager.GetNetworkMapperDir()
	if _, err := os.Stat(networkMapperDir); err == nil {
		fmt.Println("✓ Network mapper directories initialized")

		// Check for specific directories
		dirs := []struct {
			path string
			name string
		}{
			{configManager.GetResultsDir(), "results"},
			{configManager.GetProfilesDir(), "profiles"},
			{configManager.GetConfigDir(), "config"},
		}

		for _, dir := range dirs {
			if _, err := os.Stat(dir.path); err == nil {
				// Only show message if directory was just created
				if entries, err := os.ReadDir(dir.path); err == nil && len(entries) == 0 {
					fmt.Printf("  → Created %s directory\n", dir.name)
				}
			}
		}

		// Check for configuration files
		configFiles := []struct {
			path string
			name string
		}{
			{filepath.Join(configManager.GetConfigDir(), "settings.json"), "settings.json"},
			{filepath.Join(configManager.GetConfigDir(), "network-mapper.txt"), "network-mapper.txt"},
		}

		for _, file := range configFiles {
			if _, err := os.Stat(file.path); err == nil {
				// Check if file was just created (small size indicates new file)
				if info, err := os.Stat(file.path); err == nil && info.Size() > 0 {
					fmt.Printf("  → Created %s configuration\n", file.name)
				}
			}
		}
	}
}

func main() {
	// Ensure all required .txt files exist
	ensureTxtFilesExist()

	// Ensure network-mapper directories and configuration files exist
	ensureNetworkMapperExists()

	config := cracker.AttackConfig{
		MaxThreads:   10,
		Protocol:     "http",
		Port:         80,
		Timeout:      5 * time.Second,
		ShowAttempts: false,
	}

	menu := consolemenu.New(&config)

	for {
		menu.Display()
		if !menu.Process() {
			break
		}
	}
}
