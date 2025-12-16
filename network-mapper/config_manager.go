package networkmapper

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/letgo/paths"
)

// ConfigManager handles configuration file operations for the network mapper
type ConfigManager struct {
	dataDir string
}

// NewConfigManager creates a new ConfigManager instance
func NewConfigManager() *ConfigManager {
	return &ConfigManager{
		dataDir: paths.GetDataDir(),
	}
}

// GetDataDir returns the data directory path used by the network mapper
func (cm *ConfigManager) GetDataDir() string {
	return cm.dataDir
}

// GetNetworkMapperDir returns the network-mapper subdirectory within the data directory
func (cm *ConfigManager) GetNetworkMapperDir() string {
	return filepath.Join(cm.dataDir, "network-mapper")
}

// GetResultsDir returns the results subdirectory for storing scan results
func (cm *ConfigManager) GetResultsDir() string {
	return filepath.Join(cm.GetNetworkMapperDir(), "results")
}

// GetProfilesDir returns the profiles subdirectory for storing scan profiles
func (cm *ConfigManager) GetProfilesDir() string {
	return filepath.Join(cm.GetNetworkMapperDir(), "profiles")
}

// GetConfigDir returns the config subdirectory for storing configuration files
func (cm *ConfigManager) GetConfigDir() string {
	return filepath.Join(cm.GetNetworkMapperDir(), "config")
}

// EnsureDirectories creates all necessary directories for the network mapper
func (cm *ConfigManager) EnsureDirectories() error {
	dirs := []string{
		cm.GetNetworkMapperDir(),
		cm.GetResultsDir(),
		cm.GetProfilesDir(),
		cm.GetConfigDir(),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return nil
}

// GetDefaultResultPath returns the default path for saving scan results
func (cm *ConfigManager) GetDefaultResultPath(format OutputFormat) string {
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("scan_results_%s.%s", timestamp, format.String())
	return filepath.Join(cm.GetResultsDir(), filename)
}

// GetProfilePath returns the path for a specific scan profile
func (cm *ConfigManager) GetProfilePath(profileName string) string {
	filename := fmt.Sprintf("%s.json", profileName)
	return filepath.Join(cm.GetProfilesDir(), filename)
}

// SaveProfile saves a scan profile to the profiles directory
func (cm *ConfigManager) SaveProfile(profile ScanProfile) error {
	if err := cm.EnsureDirectories(); err != nil {
		return fmt.Errorf("failed to ensure directories: %w", err)
	}

	profilePath := cm.GetProfilePath(profile.Name)

	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal profile: %w", err)
	}

	if err := os.WriteFile(profilePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write profile file: %w", err)
	}

	return nil
}

// LoadProfile loads a scan profile from the profiles directory
func (cm *ConfigManager) LoadProfile(profileName string) (*ScanProfile, error) {
	profilePath := cm.GetProfilePath(profileName)

	if _, err := os.Stat(profilePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("profile not found: %s", profileName)
	}

	data, err := os.ReadFile(profilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read profile file: %w", err)
	}

	var profile ScanProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("failed to unmarshal profile: %w", err)
	}

	return &profile, nil
}

// ListProfiles returns all available scan profiles
func (cm *ConfigManager) ListProfiles() ([]ScanProfile, error) {
	profilesDir := cm.GetProfilesDir()

	// Check if profiles directory exists
	if _, err := os.Stat(profilesDir); os.IsNotExist(err) {
		// Return default profiles if directory doesn't exist
		return cm.getDefaultProfiles(), nil
	}

	entries, err := os.ReadDir(profilesDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read profiles directory: %w", err)
	}

	var profiles []ScanProfile

	// Add default profiles first
	profiles = append(profiles, cm.getDefaultProfiles()...)

	// Add custom profiles
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		profileName := entry.Name()[:len(entry.Name())-5] // Remove .json extension

		// Skip if it's a default profile (avoid duplicates)
		if cm.isDefaultProfile(profileName) {
			continue
		}

		profile, err := cm.LoadProfile(profileName)
		if err != nil {
			// Log error but continue with other profiles
			continue
		}

		profiles = append(profiles, *profile)
	}

	return profiles, nil
}

// DeleteProfile removes a custom scan profile
func (cm *ConfigManager) DeleteProfile(profileName string) error {
	// Don't allow deletion of default profiles
	if cm.isDefaultProfile(profileName) {
		return fmt.Errorf("cannot delete default profile: %s", profileName)
	}

	profilePath := cm.GetProfilePath(profileName)

	if _, err := os.Stat(profilePath); os.IsNotExist(err) {
		return fmt.Errorf("profile not found: %s", profileName)
	}

	if err := os.Remove(profilePath); err != nil {
		return fmt.Errorf("failed to delete profile file: %w", err)
	}

	return nil
}

// getDefaultProfiles returns the built-in scan profiles
func (cm *ConfigManager) getDefaultProfiles() []ScanProfile {
	return []ScanProfile{
		{
			Name:        "quick",
			Description: "Quick scan of top 100 most common ports",
			Ports:       getTopPorts(100),
			ScanType:    ScanTypeTCPConnect,
			Timing: TimingProfile{
				ConnectTimeout:    5 * time.Second,
				ReadTimeout:       3 * time.Second,
				DelayBetweenPorts: 0,
				DelayBetweenHosts: 0,
				MaxRetries:        1,
			},
			Options: ScanOptions{
				ServiceDetection: false,
				OSDetection:      false,
				AggressiveMode:   false,
				StealthMode:      false,
				FragmentPackets:  false,
			},
		},
		{
			Name:        "comprehensive",
			Description: "Comprehensive scan of top 1000 ports with service detection",
			Ports:       getTopPorts(1000),
			ScanType:    ScanTypeTCPSYN,
			Timing: TimingProfile{
				ConnectTimeout:    5 * time.Second,
				ReadTimeout:       5 * time.Second,
				DelayBetweenPorts: 0,
				DelayBetweenHosts: 0,
				MaxRetries:        2,
			},
			Options: ScanOptions{
				ServiceDetection: true,
				OSDetection:      true,
				AggressiveMode:   true,
				StealthMode:      false,
				FragmentPackets:  false,
			},
		},
		{
			Name:        "stealth",
			Description: "Stealth scan with slow timing and evasion techniques",
			Ports:       getTopPorts(200),
			ScanType:    ScanTypeTCPSYN,
			Timing: TimingProfile{
				ConnectTimeout:    10 * time.Second,
				ReadTimeout:       10 * time.Second,
				DelayBetweenPorts: 100 * time.Millisecond,
				DelayBetweenHosts: 500 * time.Millisecond,
				MaxRetries:        1,
			},
			Options: ScanOptions{
				ServiceDetection: true,
				OSDetection:      false,
				AggressiveMode:   false,
				StealthMode:      true,
				FragmentPackets:  true,
			},
		},
		{
			Name:        "vulnerability",
			Description: "Vulnerability scan focusing on common vulnerability ports",
			Ports:       getVulnerabilityPorts(),
			ScanType:    ScanTypeTCPConnect,
			Timing: TimingProfile{
				ConnectTimeout:    8 * time.Second,
				ReadTimeout:       8 * time.Second,
				DelayBetweenPorts: 0,
				DelayBetweenHosts: 0,
				MaxRetries:        2,
			},
			Options: ScanOptions{
				ServiceDetection: true,
				OSDetection:      true,
				AggressiveMode:   true,
				StealthMode:      false,
				FragmentPackets:  false,
			},
		},
	}
}

// isDefaultProfile checks if a profile name is a default profile
func (cm *ConfigManager) isDefaultProfile(profileName string) bool {
	defaultNames := []string{"quick", "comprehensive", "stealth", "vulnerability"}
	for _, name := range defaultNames {
		if name == profileName {
			return true
		}
	}
	return false
}

// getTopPorts returns the top N most common ports
func getTopPorts(n int) []int {
	// Top 1000 most common ports (first 100 shown, no duplicates)
	topPorts := []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
		1723, 3306, 3389, 5432, 5900, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007,
		7000, 7001, 7002, 7003, 7004, 7005, 7006, 7007, 7008, 7009, 8000, 8008, 8080, 8443, 8888,
		9000, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009, 9010, 9011, 9012, 9013, 9014, 9015,
		10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165, 49167, 49175, 49176,
		1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044,
		1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060,
	}

	if n > len(topPorts) {
		// If requesting more than available, return all and fill with sequential ports
		result := make([]int, n)
		copy(result, topPorts)

		// Use a map to track used ports to avoid duplicates
		usedPorts := make(map[int]bool)
		for _, port := range topPorts {
			usedPorts[port] = true
		}

		// Fill remaining slots with sequential ports, skipping duplicates
		currentPort := 1
		for i := len(topPorts); i < n; i++ {
			for usedPorts[currentPort] {
				currentPort++
				if currentPort > 65535 {
					// If we've exhausted all valid ports, break
					return result[:i]
				}
			}
			result[i] = currentPort
			usedPorts[currentPort] = true
			currentPort++
		}
		return result
	}

	return topPorts[:n]
}

// getVulnerabilityPorts returns ports commonly associated with vulnerabilities
func getVulnerabilityPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
		1433, 1521, 3306, 3389, 5432, 5900, 6379, 11211, 27017, 50070,
		// Web application ports
		8000, 8008, 8080, 8443, 8888, 9000, 9200, 9300,
		// Database ports
		1521, 1433, 3306, 5432, 6379, 27017, 50070,
		// Remote access ports
		3389, 5900, 5901, 5902, 5903, 5904, 5905,
		// Common service ports
		161, 162, 389, 636, 1024, 1025, 2049, 2121, 2375, 2376,
	}
}

// InitializeDefaultFiles creates default configuration files if they don't exist
func (cm *ConfigManager) InitializeDefaultFiles() error {
	if err := cm.EnsureDirectories(); err != nil {
		return fmt.Errorf("failed to ensure directories: %w", err)
	}

	// Create default JSON configuration file
	configPath := filepath.Join(cm.GetConfigDir(), "settings.json")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		defaultConfig := map[string]interface{}{
			"default_timeout":     "5s",
			"default_threads":     50,
			"default_format":      "text",
			"auto_service_detect": true,
			"auto_os_detect":      false,
		}

		data, err := json.MarshalIndent(defaultConfig, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal default config: %w", err)
		}

		if err := os.WriteFile(configPath, data, 0644); err != nil {
			return fmt.Errorf("failed to write default config: %w", err)
		}
	}

	// Create default Letgo-style configuration file following established patterns
	letgoConfigPath := filepath.Join(cm.GetConfigDir(), "network-mapper.txt")
	if _, err := os.Stat(letgoConfigPath); os.IsNotExist(err) {
		defaultLetgoConfig := `# Network Mapper Configuration
# This file defines default parameters for network scanning operations.
# Uncomment and modify parameters as needed. Commented parameters use default values.

# ==============================================================================
# SCAN DEFAULTS
# ==============================================================================

# Default scan timeout in seconds (default: 5)
DefaultTimeout=5

# Default number of concurrent threads (default: 50)
DefaultThreads=50

# Default output format: text, json, xml (default: text)
DefaultFormat=text

# ==============================================================================
# DETECTION SETTINGS
# ==============================================================================

# Automatically detect services on open ports (true/false, default: true)
AutoServiceDetect=true

# Automatically perform OS fingerprinting (true/false, default: false)
AutoOSDetect=false

# ==============================================================================
# TIMING PROFILES
# ==============================================================================

# Quick scan timeout in seconds (default: 3)
# QuickScanTimeout=3

# Comprehensive scan timeout in seconds (default: 8)
# ComprehensiveScanTimeout=8

# Stealth scan timeout in seconds (default: 15)
# StealthScanTimeout=15

# ==============================================================================
# PORT LISTS
# ==============================================================================

# Default port list size for quick scans (default: 100)
# QuickScanPorts=100

# Default port list size for comprehensive scans (default: 1000)
# ComprehensiveScanPorts=1000

# ==============================================================================
# INTEGRATION SETTINGS
# ==============================================================================

# Automatically export web services to valid-url.txt (true/false, default: false)
# AutoExportWebServices=false

# Automatically export auth services for brute force (true/false, default: false)
# AutoExportAuthServices=false

# Automatically export DDoS targets (true/false, default: false)
# AutoExportDDoSTargets=false
`

		if err := os.WriteFile(letgoConfigPath, []byte(defaultLetgoConfig), 0644); err != nil {
			return fmt.Errorf("failed to write Letgo-style config: %w", err)
		}
	}

	return nil
}

// LoadLetgoConfig loads configuration from the Letgo-style text file
func (cm *ConfigManager) LoadLetgoConfig() (map[string]string, error) {
	configPath := filepath.Join(cm.GetConfigDir(), "network-mapper.txt")

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Return default values if file doesn't exist
		return map[string]string{
			"DefaultTimeout":    "5",
			"DefaultThreads":    "50",
			"DefaultFormat":     "text",
			"AutoServiceDetect": "true",
			"AutoOSDetect":      "false",
		}, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	config := make(map[string]string)
	lines := strings.Split(string(data), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse key=value pairs
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				config[key] = value
			}
		}
	}

	return config, nil
}

// SaveLetgoConfig saves configuration to the Letgo-style text file
func (cm *ConfigManager) SaveLetgoConfig(config map[string]string) error {
	if err := cm.EnsureDirectories(); err != nil {
		return fmt.Errorf("failed to ensure directories: %w", err)
	}

	configPath := filepath.Join(cm.GetConfigDir(), "network-mapper.txt")

	// Read existing file to preserve comments and structure
	var lines []string
	if data, err := os.ReadFile(configPath); err == nil {
		lines = strings.Split(string(data), "\n")
	}

	// Update existing values or add new ones
	updatedLines := make([]string, 0, len(lines))
	updatedKeys := make(map[string]bool)

	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)

		// Check if this line contains a key=value pair
		if strings.Contains(trimmedLine, "=") && !strings.HasPrefix(trimmedLine, "#") {
			parts := strings.SplitN(trimmedLine, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				if newValue, exists := config[key]; exists {
					// Update with new value
					updatedLines = append(updatedLines, fmt.Sprintf("%s=%s", key, newValue))
					updatedKeys[key] = true
				} else {
					// Keep existing line
					updatedLines = append(updatedLines, line)
				}
			} else {
				updatedLines = append(updatedLines, line)
			}
		} else {
			// Keep comments and empty lines
			updatedLines = append(updatedLines, line)
		}
	}

	// Add any new keys that weren't in the original file
	for key, value := range config {
		if !updatedKeys[key] {
			updatedLines = append(updatedLines, fmt.Sprintf("%s=%s", key, value))
		}
	}

	// Write updated content
	content := strings.Join(updatedLines, "\n")
	if err := os.WriteFile(configPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// GetConfigValue gets a configuration value from the Letgo-style config file
func (cm *ConfigManager) GetConfigValue(key string, defaultValue string) string {
	config, err := cm.LoadLetgoConfig()
	if err != nil {
		return defaultValue
	}

	if value, exists := config[key]; exists {
		return value
	}

	return defaultValue
}

// SetConfigValue sets a configuration value in the Letgo-style config file
func (cm *ConfigManager) SetConfigValue(key string, value string) error {
	config, err := cm.LoadLetgoConfig()
	if err != nil {
		// If we can't load existing config, create a new one
		config = make(map[string]string)
	}

	config[key] = value
	return cm.SaveLetgoConfig(config)
}
