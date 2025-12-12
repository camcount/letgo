package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	consolemenu "github.com/letgo/console-menu"
	"github.com/letgo/cracker"
	"github.com/letgo/ddos-scanner"
)

// List of required .txt files
var requiredTxtFiles = []string{
	"users.txt",
	"passwords.txt",
	"cURL-Bruteforce.txt",
	"valid-url.txt",
	"results.txt",
	"cURL-DDOS.txt",
	"user-agent.txt",
}

// List of required proxy files
var requiredProxyFiles = []string{
	"proxy/raw-proxy.txt",
	"proxy/proxy.txt",
}

// Ensure all required .txt files exist, create if missing
func ensureTxtFilesExist() {
	for _, file := range requiredTxtFiles {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			f, err := os.Create(file)
			if err != nil {
				fmt.Printf("Error creating %s: %v\n", file, err)
			} else {
				f.Close()
				fmt.Printf("Created missing file: %s\n", file)
			}
		}
	}

	// Create proxy directory if it doesn't exist
	if _, err := os.Stat("proxy"); os.IsNotExist(err) {
		if err := os.Mkdir("proxy", 0755); err != nil {
			fmt.Printf("Error creating proxy directory: %v\n", err)
		} else {
			fmt.Println("Created proxy directory")
		}
	}

	// Create required proxy files
	for _, file := range requiredProxyFiles {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			f, err := os.Create(file)
			if err != nil {
				fmt.Printf("Error creating %s: %v\n", file, err)
			} else {
				f.Close()
				fmt.Printf("Created missing file: %s\n", file)
			}
		}
	}
}

// Ensure DDoS targets directory exists and move cURL-DDOS.txt if needed
func ensureDDOSTargetsExist() {
	// Create ddos-targets directory
	if err := ddosscanner.EnsureDDOSTargetsDir(); err != nil {
		fmt.Printf("Error creating ddos-targets directory: %v\n", err)
		return
	}

	// Move cURL-DDOS.txt from root to ddos-targets if it exists
	if err := ddosscanner.MoveCURLDDOSFile(); err != nil {
		// Don't show error if file doesn't exist (that's fine)
		if _, statErr := os.Stat("cURL-DDOS.txt"); statErr == nil {
			fmt.Printf("Warning: Could not move cURL-DDOS.txt: %v\n", err)
		}
	} else {
		// Check if file was actually moved (it existed and was moved)
		if _, err := os.Stat(filepath.Join("ddos-targets", "cURL-DDOS.txt")); err == nil {
			fmt.Println("Moved cURL-DDOS.txt to ddos-targets/")
		}
	}
}

// Ensure DDoS templates directory and base template exist
func ensureDDoSTemplatesExist() {
	templatesDir := "ddos-templates"

	// Create templates directory if it doesn't exist
	if _, err := os.Stat(templatesDir); os.IsNotExist(err) {
		if err := os.Mkdir(templatesDir, 0755); err != nil {
			fmt.Printf("Error creating %s directory: %v\n", templatesDir, err)
			return
		}
		fmt.Println("Created ddos-templates directory")
	}

	// Create base template file if it doesn't exist
	baseTemplatePath := "ddos-templates/base-ddos-template.txt"
	if _, err := os.Stat(baseTemplatePath); os.IsNotExist(err) {
		baseTemplateContent := `# DDoS Attack Configuration Template
# This file defines all configurable parameters for DDoS attacks
# Uncomment and modify parameters as needed. Commented parameters use default values.

# ==============================================================================
# BASIC CONFIGURATION (Required)
# ==============================================================================

# Target URL for the attack
TargetURL=https://example.com/api/endpoint

# HTTP Method (GET, POST, PUT, DELETE, HEAD, etc.)
Method=GET

# Attack mode: flood, slowloris, mixed, http2-stream-flood, rudy
AttackMode=flood

# ==============================================================================
# PERFORMANCE SETTINGS
# ==============================================================================

# Number of concurrent threads/workers (default: 500)
MaxThreads=500

# Attack duration in seconds (default: 60)
DurationSeconds=60

# Request timeout in seconds (default: 5)
TimeoutSeconds=5

# Requests per second limit (0 = unlimited, default: 0)
RateLimit=0

# ==============================================================================
# HTTP CONFIGURATION
# ==============================================================================

# Content-Type header (optional)
# ContentType=application/json

# HTTP request body (optional, useful for POST requests)
# Body={"key":"value"}

# Follow HTTP redirects (true/false, default: true)
FollowRedirects=true

# Reuse TCP connections for multiple requests (true/false, default: true)
ReuseConnections=true

# ==============================================================================
# PROXY CONFIGURATION
# ==============================================================================

# Enable proxy usage (true/false, default: false)
UseProxy=false

# Proxy list file path (one proxy per line, format: http://ip:port or https://ip:port)
# ProxyListFile=proxy/proxy.txt

# Rotate through proxies for each request (true/false, default: false)
RotateProxy=false

# ==============================================================================
# USER AGENT CONFIGURATION
# ==============================================================================

# Use custom user agents from file (true/false, default: true)
UseCustomUserAgents=true

# Custom user agents file path (one per line, default: user-agent.txt)
# UserAgentFilePath=user-agent.txt

# ==============================================================================
# SLOWLORIS SPECIFIC SETTINGS
# ==============================================================================
# Only applicable when AttackMode=slowloris or AttackMode=mixed

# Delay between sending partial HTTP headers in seconds (default: 10)
# SlowlorisDelaySeconds=10

# ==============================================================================
# RUDY (R-U-Dead-Yet) SPECIFIC SETTINGS
# ==============================================================================
# Only applicable when AttackMode=rudy

# Delay between sending bytes in seconds (default: 10)
# RUDYDelaySeconds=10

# Size of POST body for RUDY attack in bytes (default: 1048576 = 1MB)
# RUDYBodySize=1048576

# ==============================================================================
# HTTP/2 CONFIGURATION
# ==============================================================================

# Enable HTTP/2 support (true/false, default: false)
# Only works with HTTPS targets
UseHTTP2=false

# Maximum HTTP/2 streams per connection (default: 100)
# MaxStreamsPerConn=100

# ==============================================================================
# ADVANCED HTTP SETTINGS
# ==============================================================================

# Enable HTTP pipelining (true/false, default: false)
UsePipelining=false

# Use adaptive rate limiting based on server response (true/false, default: false)
AdaptiveRateLimit=false

# ==============================================================================
# TLS/SSL ATTACK CONFIGURATION
# ==============================================================================

# Enable TLS attack combinations (true/false, default: false)
UseTLSAttack=false

# Force TLS on HTTP URLs (true/false, default: false)
# ForceTLS=false

# Enable TLS Handshake Flood (true/false, default: false)
# Initiates many TLS handshakes without completing HTTP requests
# TLSHandshakeFlood=false

# Enable TLS Renegotiation attacks (true/false, default: false)
# Force TLS renegotiation on connections
# TLSRenegotiation=false

# Minimum TLS version: 0x0301 (TLS 1.0), 0x0302 (TLS 1.1), 0x0303 (TLS 1.2), 0x0304 (TLS 1.3)
# 0 = use default (default: 0)
# TLSMinVersion=0x0303

# Maximum TLS version: 0x0301 (TLS 1.0), 0x0302 (TLS 1.1), 0x0303 (TLS 1.2), 0x0304 (TLS 1.3)
# 0 = use default (default: 0)
# TLSMaxVersion=0x0304

# ==============================================================================
# CUSTOM HTTP HEADERS (Optional)
# ==============================================================================
# Format: Header-Name=Header-Value
# Example headers below - uncomment and modify as needed

# Authorization=Bearer your-token-here
# User-Agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
# Accept=application/json
# Accept-Language=en-US,en;q=0.9
# Cache-Control=no-cache
# Pragma=no-cache
# Referer=https://example.com
`
		f, err := os.Create(baseTemplatePath)
		if err != nil {
			fmt.Printf("Error creating %s: %v\n", baseTemplatePath, err)
			return
		}
		defer f.Close()

		if _, err := f.WriteString(baseTemplateContent); err != nil {
			fmt.Printf("Error writing to %s: %v\n", baseTemplatePath, err)
			return
		}
		fmt.Println("Created base-ddos-template.txt")
	}
}

func main() {
	// Ensure all required .txt files exist
	ensureTxtFilesExist()

	// Ensure DDoS targets directory exists and move cURL-DDOS.txt if needed
	ensureDDOSTargetsExist()

	// Ensure DDoS templates directory and base template exist
	ensureDDoSTemplatesExist()

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
