package networkmapper

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/quick"
	"time"

	"github.com/letgo/paths"
)

// TestFileSystemConsistency tests Property 20: File System Consistency
// **Feature: network-mapper, Property 20: File System Consistency**
// **Validates: Requirements 9.4, 9.5**
func TestFileSystemConsistency(t *testing.T) {
	// Property 20: File System Consistency
	// For any Network_Mapper file operation, the same data directory structure should be used as other Letgo modules
	property := func() bool {
		// Create a new config manager
		cm := NewConfigManager()

		// Verify that the base data directory matches Letgo's data directory
		expectedDataDir := paths.GetDataDir()
		actualDataDir := cm.GetDataDir()

		if actualDataDir != expectedDataDir {
			t.Logf("Data directory mismatch: expected %s, got %s", expectedDataDir, actualDataDir)
			return false
		}

		// Verify that network-mapper subdirectory is within the data directory
		networkMapperDir := cm.GetNetworkMapperDir()
		expectedNetworkMapperDir := filepath.Join(expectedDataDir, "network-mapper")

		if networkMapperDir != expectedNetworkMapperDir {
			t.Logf("Network mapper directory mismatch: expected %s, got %s", expectedNetworkMapperDir, networkMapperDir)
			return false
		}

		// Verify that all subdirectories are within the network-mapper directory
		resultsDir := cm.GetResultsDir()
		profilesDir := cm.GetProfilesDir()
		configDir := cm.GetConfigDir()

		expectedResultsDir := filepath.Join(networkMapperDir, "results")
		expectedProfilesDir := filepath.Join(networkMapperDir, "profiles")
		expectedConfigDir := filepath.Join(networkMapperDir, "config")

		if resultsDir != expectedResultsDir {
			t.Logf("Results directory mismatch: expected %s, got %s", expectedResultsDir, resultsDir)
			return false
		}

		if profilesDir != expectedProfilesDir {
			t.Logf("Profiles directory mismatch: expected %s, got %s", expectedProfilesDir, profilesDir)
			return false
		}

		if configDir != expectedConfigDir {
			t.Logf("Config directory mismatch: expected %s, got %s", expectedConfigDir, configDir)
			return false
		}

		// Verify that all paths use the same root data directory
		allPaths := []string{actualDataDir, networkMapperDir, resultsDir, profilesDir, configDir}
		for _, path := range allPaths {
			if !strings.HasPrefix(path, expectedDataDir) {
				t.Logf("Path %s does not use expected data directory root %s", path, expectedDataDir)
				return false
			}
		}

		return true
	}

	// Run the property test with 100 iterations
	config := &quick.Config{MaxCount: 100}
	if err := quick.Check(property, config); err != nil {
		t.Errorf("Property 20 (File System Consistency) failed: %v", err)
	}
}

// TestLetgoStyleConfiguration tests the Letgo-style configuration file functionality
func TestLetgoStyleConfiguration(t *testing.T) {
	cm := NewConfigManager()

	// Clean up any existing config file first to ensure clean test
	configPath := filepath.Join(cm.GetConfigDir(), "network-mapper.txt")
	os.Remove(configPath)

	// Initialize default files to create the Letgo-style config
	err := cm.InitializeDefaultFiles()
	if err != nil {
		t.Fatalf("Failed to initialize default files: %v", err)
	}

	// Test loading default configuration
	config, err := cm.LoadLetgoConfig()
	if err != nil {
		t.Fatalf("Failed to load Letgo config: %v", err)
	}

	// Verify default values
	expectedDefaults := map[string]string{
		"DefaultTimeout":    "5",
		"DefaultThreads":    "50",
		"DefaultFormat":     "text",
		"AutoServiceDetect": "true",
		"AutoOSDetect":      "false",
	}

	for key, expectedValue := range expectedDefaults {
		if actualValue, exists := config[key]; !exists {
			t.Errorf("Expected config key %s not found", key)
		} else if actualValue != expectedValue {
			t.Errorf("Config key %s: expected %s, got %s", key, expectedValue, actualValue)
		}
	}

	// Test getting individual config values
	timeout := cm.GetConfigValue("DefaultTimeout", "10")
	if timeout != "5" {
		t.Errorf("Expected timeout 5, got %s", timeout)
	}

	// Test getting non-existent value with default
	nonExistent := cm.GetConfigValue("NonExistentKey", "default")
	if nonExistent != "default" {
		t.Errorf("Expected default value 'default', got %s", nonExistent)
	}

	// Test setting a config value
	err = cm.SetConfigValue("DefaultThreads", "100")
	if err != nil {
		t.Fatalf("Failed to set config value: %v", err)
	}

	// Verify the value was updated
	updatedThreads := cm.GetConfigValue("DefaultThreads", "50")
	if updatedThreads != "100" {
		t.Errorf("Expected updated threads 100, got %s", updatedThreads)
	}

	// Test setting a new config value
	err = cm.SetConfigValue("NewTestKey", "testvalue")
	if err != nil {
		t.Fatalf("Failed to set new config value: %v", err)
	}

	// Verify the new value exists
	newValue := cm.GetConfigValue("NewTestKey", "notfound")
	if newValue != "testvalue" {
		t.Errorf("Expected new value 'testvalue', got %s", newValue)
	}

	// Clean up - reset the config file to defaults by removing and recreating it
	os.Remove(configPath)

	err = cm.InitializeDefaultFiles()
	if err != nil {
		t.Fatalf("Failed to reset config file: %v", err)
	}
}

// TestDirectoryCreation tests that directories are created consistently
func TestDirectoryCreation(t *testing.T) {
	cm := NewConfigManager()

	// Test directory creation
	err := cm.EnsureDirectories()
	if err != nil {
		t.Fatalf("Failed to ensure directories: %v", err)
	}

	// Verify all directories exist
	dirs := []string{
		cm.GetNetworkMapperDir(),
		cm.GetResultsDir(),
		cm.GetProfilesDir(),
		cm.GetConfigDir(),
	}

	for _, dir := range dirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Errorf("Directory was not created: %s", dir)
		}
	}
}

// TestDefaultResultPath tests that default result paths follow the expected pattern
func TestDefaultResultPath(t *testing.T) {
	cm := NewConfigManager()

	formats := []OutputFormat{OutputFormatJSON, OutputFormatXML, OutputFormatText}

	for _, format := range formats {
		path := cm.GetDefaultResultPath(format)

		// Verify path is within results directory
		resultsDir := cm.GetResultsDir()
		if !strings.HasPrefix(path, resultsDir) {
			t.Errorf("Default result path %s is not within results directory %s", path, resultsDir)
		}

		// Verify file extension matches format
		expectedExt := "." + format.String()
		if !strings.HasSuffix(path, expectedExt) {
			t.Errorf("Default result path %s does not have expected extension %s", path, expectedExt)
		}

		// Verify filename contains timestamp pattern
		filename := filepath.Base(path)
		if !strings.Contains(filename, "scan_results_") {
			t.Errorf("Default result filename %s does not contain expected prefix", filename)
		}
	}
}

// TestProfilePaths tests that profile paths follow the expected pattern
func TestProfilePaths(t *testing.T) {
	cm := NewConfigManager()

	testProfileNames := []string{"test-profile", "custom_profile", "my-scan-profile"}

	for _, profileName := range testProfileNames {
		path := cm.GetProfilePath(profileName)

		// Verify path is within profiles directory
		profilesDir := cm.GetProfilesDir()
		if !strings.HasPrefix(path, profilesDir) {
			t.Errorf("Profile path %s is not within profiles directory %s", path, profilesDir)
		}

		// Verify file extension is .json
		if !strings.HasSuffix(path, ".json") {
			t.Errorf("Profile path %s does not have .json extension", path)
		}

		// Verify filename matches profile name
		expectedFilename := profileName + ".json"
		actualFilename := filepath.Base(path)
		if actualFilename != expectedFilename {
			t.Errorf("Profile filename mismatch: expected %s, got %s", expectedFilename, actualFilename)
		}
	}
}

// TestInitializeDefaultFiles tests that default files are created properly
func TestInitializeDefaultFiles(t *testing.T) {
	cm := NewConfigManager()

	// Initialize default files
	err := cm.InitializeDefaultFiles()
	if err != nil {
		t.Fatalf("Failed to initialize default files: %v", err)
	}

	// Verify config file exists
	configPath := filepath.Join(cm.GetConfigDir(), "settings.json")
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Errorf("Default config file was not created: %s", configPath)
	}

	// Verify config file is within the expected directory structure
	expectedConfigDir := filepath.Join(cm.GetDataDir(), "network-mapper", "config")
	actualConfigDir := filepath.Dir(configPath)
	if actualConfigDir != expectedConfigDir {
		t.Errorf("Config file directory mismatch: expected %s, got %s", expectedConfigDir, actualConfigDir)
	}
}

// TestResultManagerFileSystemIntegration tests that ResultManager uses proper file system structure
func TestResultManagerFileSystemIntegration(t *testing.T) {
	rm := NewResultManager()

	// Create a test scan result
	testResult := &ScanResult{
		Timestamp: time.Now(),
		ScanConfig: ScanConfig{
			Targets: []string{"127.0.0.1"},
		},
		Hosts:      []HostResult{},
		Statistics: ScanStatistics{},
	}

	// Test saving with relative filename
	relativeFilename := "test-scan.json"
	err := rm.SaveResults(testResult, OutputFormatJSON, relativeFilename)
	if err != nil {
		t.Fatalf("Failed to save results with relative filename: %v", err)
	}

	// Verify file was created in the results directory
	cm := NewConfigManager()
	expectedPath := filepath.Join(cm.GetResultsDir(), relativeFilename)
	if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
		t.Errorf("Result file was not created in expected location: %s", expectedPath)
	}

	// Clean up
	os.Remove(expectedPath)
}
