package networkmapper

import (
	"context"
	"log"
	"math/rand"
	"reflect"
	"testing"
	"testing/quick"
	"time"
)

// TestOSDetectionExecution tests Property 10: OS Detection Execution
// **Feature: network-mapper, Property 10: OS Detection Execution**
// **Validates: Requirements 4.1**
func TestOSDetectionExecution(t *testing.T) {
	// Property 10: OS Detection Execution
	// For any target host when OS detection is enabled, network response analysis should be performed to determine the operating system

	property := func(targetIP string, openPorts []int) bool {
		// Skip invalid inputs
		if targetIP == "" || len(openPorts) == 0 {
			return true // Skip invalid test cases
		}

		// Ensure ports are in valid range
		validPorts := make([]int, 0)
		for _, port := range openPorts {
			if port > 0 && port <= 65535 {
				validPorts = append(validPorts, port)
			}
		}

		if len(validPorts) == 0 {
			return true // Skip if no valid ports
		}

		// Limit to first 5 ports to avoid excessive testing
		if len(validPorts) > 5 {
			validPorts = validPorts[:5]
		}

		// Create OS fingerprinter with short timeout for testing
		osFingerprinter := NewDefaultOSFingerprinter(500*time.Millisecond, 1, log.Default())

		// Create context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		// Perform OS detection
		result := osFingerprinter.DetectOS(ctx, targetIP, validPorts)

		// Verify that OS detection was attempted and returned a result
		// The result should have some structure even if detection fails
		if result.Family == "" {
			return false // OS detection should at least return "Unknown" for family
		}

		// Verify that matches array is initialized (even if empty)
		if result.Matches == nil {
			return false // Matches should be initialized
		}

		// Verify confidence is in valid range (0-100)
		if result.Confidence < 0 || result.Confidence > 100 {
			return false // Confidence should be between 0 and 100
		}

		// If we have matches, verify they have valid confidence values
		for _, match := range result.Matches {
			if match.Confidence < 0 || match.Confidence > 100 {
				return false // Each match confidence should be valid
			}
			if match.Name == "" {
				return false // Each match should have a name
			}
		}

		return true
	}

	// Configure quick testing
	config := &quick.Config{
		MaxCount: 100, // Run 100 iterations as specified in design
		Values: func(values []reflect.Value, rng *rand.Rand) {
			// Use only localhost to avoid network connectivity issues in tests
			values[0] = reflect.ValueOf("127.0.0.1")

			// Generate random port lists with commonly available ports
			numPorts := rng.Intn(3) + 1 // 1-3 ports to keep tests fast
			ports := make([]int, numPorts)
			// Use ports that are more likely to be available or fail quickly
			commonPorts := []int{80, 443, 22, 25}
			for i := 0; i < numPorts; i++ {
				ports[i] = commonPorts[rng.Intn(len(commonPorts))]
			}
			values[1] = reflect.ValueOf(ports)
		},
	}

	if err := quick.Check(property, config); err != nil {
		t.Errorf("Property 10 (OS Detection Execution) failed: %v", err)
	}
}

// TestOSInformationCompleteness tests Property 11: OS Information Completeness
// **Feature: network-mapper, Property 11: OS Information Completeness**
// **Validates: Requirements 4.2**
func TestOSInformationCompleteness(t *testing.T) {
	// Property 11: OS Information Completeness
	// For any completed OS fingerprinting, the output should include OS family, version, and confidence level

	property := func(targetIP string, openPorts []int) bool {
		// Skip invalid inputs
		if targetIP == "" || len(openPorts) == 0 {
			return true // Skip invalid test cases
		}

		// Ensure ports are in valid range
		validPorts := make([]int, 0)
		for _, port := range openPorts {
			if port > 0 && port <= 65535 {
				validPorts = append(validPorts, port)
			}
		}

		if len(validPorts) == 0 {
			return true // Skip if no valid ports
		}

		// Limit to first 3 ports to avoid excessive testing
		if len(validPorts) > 3 {
			validPorts = validPorts[:3]
		}

		// Create OS fingerprinter with short timeout for testing
		osFingerprinter := NewDefaultOSFingerprinter(500*time.Millisecond, 1, log.Default())

		// Create context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Perform OS detection
		result := osFingerprinter.DetectOS(ctx, targetIP, validPorts)

		// Verify completeness of OS information
		// 1. OS family must be present (even if "Unknown")
		if result.Family == "" {
			return false
		}

		// 2. OS version must be present (even if "Unknown")
		if result.Version == "" {
			return false
		}

		// 3. Confidence level must be present and valid (0-100)
		if result.Confidence < 0 || result.Confidence > 100 {
			return false
		}

		// 4. Matches array must be initialized
		if result.Matches == nil {
			return false
		}

		// 5. If there are matches, each must have complete information
		for _, match := range result.Matches {
			if match.Name == "" {
				return false // Each match must have a name
			}
			if match.Version == "" {
				return false // Each match must have a version (even if "Unknown")
			}
			if match.Confidence < 0 || match.Confidence > 100 {
				return false // Each match must have valid confidence
			}
		}

		return true
	}

	// Configure quick testing
	config := &quick.Config{
		MaxCount: 100, // Run 100 iterations as specified in design
		Values: func(values []reflect.Value, rng *rand.Rand) {
			// Use only localhost to avoid network connectivity issues in tests
			values[0] = reflect.ValueOf("127.0.0.1")

			// Generate random port lists with commonly available ports
			numPorts := rng.Intn(2) + 1 // 1-2 ports to keep tests fast
			ports := make([]int, numPorts)
			commonPorts := []int{80, 443, 22}
			for i := 0; i < numPorts; i++ {
				ports[i] = commonPorts[rng.Intn(len(commonPorts))]
			}
			values[1] = reflect.ValueOf(ports)
		},
	}

	if err := quick.Check(property, config); err != nil {
		t.Errorf("Property 11 (OS Information Completeness) failed: %v", err)
	}
}

// Unit tests for OS fingerprinter functionality

func TestNewDefaultOSFingerprinter(t *testing.T) {
	timeout := 5 * time.Second
	maxRetries := 3
	logger := log.Default()

	osf := NewDefaultOSFingerprinter(timeout, maxRetries, logger)

	if osf == nil {
		t.Fatal("NewDefaultOSFingerprinter returned nil")
	}

	if osf.timeout != timeout {
		t.Errorf("Expected timeout %v, got %v", timeout, osf.timeout)
	}

	if osf.maxRetries != maxRetries {
		t.Errorf("Expected maxRetries %d, got %d", maxRetries, osf.maxRetries)
	}

	if osf.logger != logger {
		t.Error("Logger not set correctly")
	}

	if len(osf.signatures) == 0 {
		t.Error("No OS signatures loaded")
	}
}

func TestExtractOSFamily(t *testing.T) {
	testCases := []struct {
		osName   string
		expected string
	}{
		{"Linux 2.6.x", "Linux"},
		{"Ubuntu 20.04", "Linux"},
		{"Windows 10", "Windows"},
		{"Windows Server 2019", "Windows"},
		{"macOS Monterey", "macOS"},
		{"FreeBSD 13.0", "FreeBSD"},
		{"Unknown OS", "Unknown"},
		{"Cisco IOS", "Unknown"}, // Should fall through to Unknown
	}

	for _, tc := range testCases {
		result := extractOSFamily(tc.osName)
		if result != tc.expected {
			t.Errorf("extractOSFamily(%q) = %q, expected %q", tc.osName, result, tc.expected)
		}
	}
}

func TestOSDetectionWithNoOpenPorts(t *testing.T) {
	osf := NewDefaultOSFingerprinter(2*time.Second, 1, log.Default())
	ctx := context.Background()

	result := osf.DetectOS(ctx, "127.0.0.1", []int{})

	if result.Family != "Unknown" {
		t.Errorf("Expected Family 'Unknown', got %q", result.Family)
	}

	if result.Version != "Unknown" {
		t.Errorf("Expected Version 'Unknown', got %q", result.Version)
	}

	if result.Confidence != 0.0 {
		t.Errorf("Expected Confidence 0.0, got %f", result.Confidence)
	}

	if len(result.Matches) != 0 {
		t.Errorf("Expected empty matches, got %d matches", len(result.Matches))
	}
}

func TestMatchesPattern(t *testing.T) {
	osf := NewDefaultOSFingerprinter(2*time.Second, 1, log.Default())

	testCases := []struct {
		result   string
		pattern  string
		expected bool
	}{
		{"64", "64", true},                    // Exact match
		{"65", "64", false},                   // No match
		{"65", "60-70", true},                 // Range match
		{"59", "60-70", false},                // Outside range
		{"linux", "regex:.*linux.*", true},    // Regex match
		{"windows", "regex:.*linux.*", false}, // Regex no match
		{"invalid", "regex:[invalid", false},  // Invalid regex
	}

	for _, tc := range testCases {
		result := osf.matchesPattern(tc.result, tc.pattern)
		if result != tc.expected {
			t.Errorf("matchesPattern(%q, %q) = %v, expected %v", tc.result, tc.pattern, result, tc.expected)
		}
	}
}
