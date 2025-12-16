package networkmapper

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/letgo/paths"
)

// TestFileSystemIntegrationEndToEnd tests the complete file system integration
func TestFileSystemIntegrationEndToEnd(t *testing.T) {
	// Test that the network mapper creates the proper directory structure
	cm := NewConfigManager()

	// Verify base data directory matches Letgo's structure
	expectedDataDir := paths.GetDataDir()
	if cm.GetDataDir() != expectedDataDir {
		t.Errorf("Data directory mismatch: expected %s, got %s", expectedDataDir, cm.GetDataDir())
	}

	// Initialize directories and files
	err := cm.InitializeDefaultFiles()
	if err != nil {
		t.Fatalf("Failed to initialize default files: %v", err)
	}

	// Verify network-mapper subdirectory structure exists
	networkMapperDir := cm.GetNetworkMapperDir()
	expectedNetworkMapperDir := filepath.Join(expectedDataDir, "network-mapper")
	if networkMapperDir != expectedNetworkMapperDir {
		t.Errorf("Network mapper directory mismatch: expected %s, got %s", expectedNetworkMapperDir, networkMapperDir)
	}

	// Verify all subdirectories exist
	dirs := []string{
		cm.GetResultsDir(),
		cm.GetProfilesDir(),
		cm.GetConfigDir(),
	}

	for _, dir := range dirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			t.Errorf("Directory does not exist: %s", dir)
		}
	}

	// Test profile management with file system
	pm := NewProfileManager()

	// Create and save a custom profile
	customProfile := ScanProfile{
		Name:        "test-integration-profile",
		Description: "Test profile for integration testing",
		Ports:       []int{80, 443, 8080},
		ScanType:    ScanTypeTCPConnect,
		Timing: TimingProfile{
			ConnectTimeout:    5 * time.Second,
			ReadTimeout:       3 * time.Second,
			DelayBetweenPorts: 0,
			DelayBetweenHosts: 0,
			MaxRetries:        1,
		},
		Options: ScanOptions{
			ServiceDetection: true,
			OSDetection:      false,
			AggressiveMode:   false,
			StealthMode:      false,
			FragmentPackets:  false,
		},
	}

	err = pm.SaveProfile(customProfile)
	if err != nil {
		t.Fatalf("Failed to save custom profile: %v", err)
	}

	// Verify profile file exists in the correct location
	profilePath := cm.GetProfilePath(customProfile.Name)
	if _, err := os.Stat(profilePath); os.IsNotExist(err) {
		t.Errorf("Profile file does not exist: %s", profilePath)
	}

	// Test result manager with file system
	rm := NewResultManager()

	// Create a test scan result
	testResult := &ScanResult{
		Timestamp: time.Now(),
		ScanConfig: ScanConfig{
			Targets: []string{"127.0.0.1"},
			Ports:   []int{80, 443},
		},
		Hosts: []HostResult{
			{
				Target: "127.0.0.1",
				Status: HostUp,
				Ports: []PortResult{
					{
						Port:     80,
						Protocol: "tcp",
						State:    PortOpen,
						Service: ServiceInfo{
							Name: "http",
						},
					},
				},
			},
		},
		Statistics: ScanStatistics{
			HostsScanned: 1,
			PortsScanned: 2,
			OpenPorts:    1,
		},
	}

	// Save result with default path (should go to results directory)
	err = rm.SaveResults(testResult, OutputFormatJSON, "")
	if err != nil {
		t.Fatalf("Failed to save results: %v", err)
	}

	// Verify result file was created in the results directory
	resultsDir := cm.GetResultsDir()
	entries, err := os.ReadDir(resultsDir)
	if err != nil {
		t.Fatalf("Failed to read results directory: %v", err)
	}

	found := false
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			found = true
			break
		}
	}

	if !found {
		t.Error("No JSON result file found in results directory")
	}

	// Clean up test files
	os.Remove(profilePath)
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			os.Remove(filepath.Join(resultsDir, entry.Name()))
		}
	}
}
