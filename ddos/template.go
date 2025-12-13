package ddos

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/letgo/paths"
)

// LoadTemplateFile loads a DDoS configuration from a template file
func LoadTemplateFile(filePath string) (*DDoSConfig, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open template file: %w", err)
	}
	defer file.Close()

	config := &DDoSConfig{
		// Set defaults
		Method:              "GET",
		AttackMode:          ModeFlood,
		MaxThreads:          500,
		Duration:            60 * time.Second,
		Timeout:             5 * time.Second,
		RateLimit:           0,
		FollowRedirects:     true,
		ReuseConnections:    true,
		UseCustomUserAgents: true,
		UseProxy:            false,
		RotateProxy:         false,
		UseTLSAttack:        false,
		ForceTLS:            false,
		TLSHandshakeFlood:   false,
		TLSRenegotiation:    false,
		UseHTTP2:            false,
		UsePipelining:       false,
		AdaptiveRateLimit:   false,
		MaxStreamsPerConn:   100,
		SlowlorisDelay:      10 * time.Second,
		RUDYDelay:           10 * time.Second,
		RUDYBodySize:        1048576, // 1MB
		Headers:             make(map[string]string),
	}

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse key=value format
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid format at line %d: %s", lineNum, line)
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Parse configuration
		switch key {
		case "TargetURL":
			config.TargetURL = value
		case "Method":
			config.Method = strings.ToUpper(value)
		case "AttackMode":
			mode := AttackMode(strings.ToLower(value))
			switch mode {
			case ModeFlood, ModeSlowloris, ModeMixed, ModeHTTP2StreamFlood, ModeRUDY:
				config.AttackMode = mode
			default:
				return nil, fmt.Errorf("invalid attack mode at line %d: %s", lineNum, value)
			}
		case "MaxThreads":
			if v, err := strconv.Atoi(value); err == nil && v > 0 {
				config.MaxThreads = v
			}
		case "DurationSeconds":
			if v, err := strconv.Atoi(value); err == nil && v > 0 {
				config.Duration = time.Duration(v) * time.Second
			}
		case "TimeoutSeconds":
			if v, err := strconv.Atoi(value); err == nil && v > 0 {
				config.Timeout = time.Duration(v) * time.Second
			}
		case "RateLimit":
			if v, err := strconv.Atoi(value); err == nil && v >= 0 {
				config.RateLimit = v
			}
		case "ContentType":
			config.ContentType = value
		case "Body":
			config.Body = value
		case "FollowRedirects":
			config.FollowRedirects = parseBool(value)
		case "ReuseConnections":
			config.ReuseConnections = parseBool(value)
		case "UseProxy":
			config.UseProxy = parseBool(value)
		case "ProxyListFile":
			// Load proxies from file if specified
			if proxies, err := loadProxiesFromFile(value); err == nil {
				config.ProxyList = proxies
			}
		case "RotateProxy":
			config.RotateProxy = parseBool(value)
		case "UseCustomUserAgents":
			config.UseCustomUserAgents = parseBool(value)
		case "UserAgentFilePath":
			config.UserAgentFilePath = value
		case "SlowlorisDelaySeconds":
			if v, err := strconv.Atoi(value); err == nil && v > 0 {
				config.SlowlorisDelay = time.Duration(v) * time.Second
			}
		case "RUDYDelaySeconds":
			if v, err := strconv.Atoi(value); err == nil && v > 0 {
				config.RUDYDelay = time.Duration(v) * time.Second
			}
		case "RUDYBodySize":
			if v, err := strconv.Atoi(value); err == nil && v > 0 {
				config.RUDYBodySize = v
			}
		case "UseHTTP2":
			config.UseHTTP2 = parseBool(value)
		case "MaxStreamsPerConn":
			if v, err := strconv.Atoi(value); err == nil && v > 0 {
				config.MaxStreamsPerConn = v
			}
		case "UsePipelining":
			config.UsePipelining = parseBool(value)
		case "AdaptiveRateLimit":
			config.AdaptiveRateLimit = parseBool(value)
		case "UseTLSAttack":
			config.UseTLSAttack = parseBool(value)
		case "ForceTLS":
			config.ForceTLS = parseBool(value)
		case "TLSHandshakeFlood":
			config.TLSHandshakeFlood = parseBool(value)
		case "TLSRenegotiation":
			config.TLSRenegotiation = parseBool(value)
		case "TLSMinVersion":
			if v, err := strconv.ParseUint(value, 0, 16); err == nil {
				config.TLSMinVersion = uint16(v)
			}
		case "TLSMaxVersion":
			if v, err := strconv.ParseUint(value, 0, 16); err == nil {
				config.TLSMaxVersion = uint16(v)
			}
		default:
			// Treat as custom header if key contains no spaces and looks like a header
			if !strings.Contains(key, " ") && (strings.Contains(key, "-") || !strings.ContainsAny(key, "=")) {
				config.Headers[key] = value
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading template file: %w", err)
	}

	// TargetURL is NOT required for templates - it will be provided from cURL config
	// All other validations happen when applying template to actual targets

	return config, nil
}

// SaveConfigAsTemplate saves a DDoS configuration to a template file
func SaveConfigAsTemplate(config *DDoSConfig, fileName string) (string, error) {
	// Ensure templates directory exists
	dataDir := paths.GetDataDir()
	templatesDir := filepath.Join(dataDir, "ddos-templates")
	if _, err := os.Stat(templatesDir); os.IsNotExist(err) {
		if err := os.MkdirAll(templatesDir, 0755); err != nil {
			return "", fmt.Errorf("failed to create templates directory: %w", err)
		}
	}

	// Generate full path
	filePath := filepath.Join(templatesDir, fileName)

	// Check if file already exists
	if _, err := os.Stat(filePath); err == nil {
		return "", fmt.Errorf("template file %s already exists", filePath)
	}

	file, err := os.Create(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to create template file: %w", err)
	}
	defer file.Close()

	// Write configuration as key=value pairs
	writer := bufio.NewWriter(file)

	writer.WriteString("# DDoS Attack Configuration Template\n")
	writer.WriteString("# Auto-generated template\n")
	writer.WriteString("# Note: Target URL, HTTP Method, Headers, and Body are obtained from cURL config\n\n")

	writer.WriteString("# ==============================================================================\n")
	writer.WriteString("# ATTACK MODE\n")
	writer.WriteString("# ==============================================================================\n")
	writer.WriteString(fmt.Sprintf("AttackMode=%s\n", config.AttackMode))

	writer.WriteString("\n# ==============================================================================\n")
	writer.WriteString("# PERFORMANCE SETTINGS\n")
	writer.WriteString("# ==============================================================================\n")
	writer.WriteString(fmt.Sprintf("MaxThreads=%d\n", config.MaxThreads))
	writer.WriteString(fmt.Sprintf("DurationSeconds=%.0f\n", config.Duration.Seconds()))
	writer.WriteString(fmt.Sprintf("TimeoutSeconds=%.0f\n", config.Timeout.Seconds()))
	writer.WriteString(fmt.Sprintf("RateLimit=%d\n", config.RateLimit))

	writer.WriteString("\n# ==============================================================================\n")
	writer.WriteString("# HTTP CONFIGURATION\n")
	writer.WriteString("# ==============================================================================\n")
	writer.WriteString(fmt.Sprintf("FollowRedirects=%v\n", config.FollowRedirects))
	writer.WriteString(fmt.Sprintf("ReuseConnections=%v\n", config.ReuseConnections))

	writer.WriteString("\n# ==============================================================================\n")
	writer.WriteString("# PROXY CONFIGURATION\n")
	writer.WriteString("# ==============================================================================\n")
	writer.WriteString(fmt.Sprintf("UseProxy=%v\n", config.UseProxy))
	if config.UseProxy && len(config.ProxyList) > 0 {
		writer.WriteString(fmt.Sprintf("RotateProxy=%v\n", config.RotateProxy))
	}

	writer.WriteString("\n# ==============================================================================\n")
	writer.WriteString("# USER AGENT CONFIGURATION\n")
	writer.WriteString("# ==============================================================================\n")
	writer.WriteString(fmt.Sprintf("UseCustomUserAgents=%v\n", config.UseCustomUserAgents))
	if config.UserAgentFilePath != "" {
		writer.WriteString(fmt.Sprintf("UserAgentFilePath=%s\n", config.UserAgentFilePath))
	}

	// Write mode-specific settings
	if config.AttackMode == ModeSlowloris || config.AttackMode == ModeMixed {
		writer.WriteString("\n# ==============================================================================\n")
		writer.WriteString("# SLOWLORIS SPECIFIC SETTINGS\n")
		writer.WriteString("# ==============================================================================\n")
		writer.WriteString(fmt.Sprintf("SlowlorisDelaySeconds=%.0f\n", config.SlowlorisDelay.Seconds()))
	}

	if config.AttackMode == ModeRUDY || config.AttackMode == ModeMixed {
		writer.WriteString("\n# ==============================================================================\n")
		writer.WriteString("# RUDY (R-U-Dead-Yet) SPECIFIC SETTINGS\n")
		writer.WriteString("# ==============================================================================\n")
		writer.WriteString(fmt.Sprintf("RUDYDelaySeconds=%.0f\n", config.RUDYDelay.Seconds()))
		writer.WriteString(fmt.Sprintf("RUDYBodySize=%d\n", config.RUDYBodySize))
	}

	// Write HTTP/2 settings
	if config.AttackMode == ModeHTTP2StreamFlood || config.UseHTTP2 {
		writer.WriteString("\n# ==============================================================================\n")
		writer.WriteString("# HTTP/2 CONFIGURATION\n")
		writer.WriteString("# ==============================================================================\n")
		writer.WriteString(fmt.Sprintf("UseHTTP2=%v\n", config.UseHTTP2))
		writer.WriteString(fmt.Sprintf("MaxStreamsPerConn=%d\n", config.MaxStreamsPerConn))
	}

	writer.WriteString("\n# ==============================================================================\n")
	writer.WriteString("# ADVANCED HTTP SETTINGS\n")
	writer.WriteString("# ==============================================================================\n")
	writer.WriteString(fmt.Sprintf("UsePipelining=%v\n", config.UsePipelining))
	if config.RateLimit > 0 {
		writer.WriteString(fmt.Sprintf("AdaptiveRateLimit=%v\n", config.AdaptiveRateLimit))
	}

	// Write TLS settings
	if config.UseTLSAttack {
		writer.WriteString("\n# ==============================================================================\n")
		writer.WriteString("# TLS/SSL ATTACK CONFIGURATION\n")
		writer.WriteString("# ==============================================================================\n")
		writer.WriteString(fmt.Sprintf("UseTLSAttack=%v\n", config.UseTLSAttack))
		writer.WriteString(fmt.Sprintf("ForceTLS=%v\n", config.ForceTLS))
		writer.WriteString(fmt.Sprintf("TLSHandshakeFlood=%v\n", config.TLSHandshakeFlood))
		writer.WriteString(fmt.Sprintf("TLSRenegotiation=%v\n", config.TLSRenegotiation))
		if config.TLSMinVersion > 0 {
			writer.WriteString(fmt.Sprintf("TLSMinVersion=0x%04x\n", config.TLSMinVersion))
		}
		if config.TLSMaxVersion > 0 {
			writer.WriteString(fmt.Sprintf("TLSMaxVersion=0x%04x\n", config.TLSMaxVersion))
		}
	}

	// Note: Custom HTTP headers are obtained from cURL config, not stored in template
	// Headers in config.Headers are from cURL and should not be saved to template

	writer.Flush()

	return filePath, nil
}

// ListAvailableTemplates returns a list of available template files
func ListAvailableTemplates() ([]string, error) {
	dataDir := paths.GetDataDir()
	templatesDir := filepath.Join(dataDir, "ddos-templates")

	entries, err := os.ReadDir(templatesDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read templates directory: %w", err)
	}

	var templates []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".txt") {
			templates = append(templates, entry.Name())
		}
	}

	return templates, nil
}

// Helper function to parse boolean values
func parseBool(value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	return v == "true" || v == "yes" || v == "1" || v == "y"
}

// Helper function to load proxies from file
func loadProxiesFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var proxies []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			proxies = append(proxies, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return proxies, nil
}
