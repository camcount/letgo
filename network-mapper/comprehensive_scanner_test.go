package networkmapper

import (
	"context"
	"testing"
	"time"
)

// TestComprehensiveScannerCreation tests that the comprehensive scanner can be created successfully
func TestComprehensiveScannerCreation(t *testing.T) {
	config := DefaultComprehensiveScannerConfig()
	config.LogToFile = false // Disable file logging for tests

	scanner, err := NewComprehensiveScanner(config)
	if err != nil {
		t.Fatalf("Failed to create comprehensive scanner: %v", err)
	}
	defer scanner.Close()

	// Verify components are created
	if scanner.Engine == nil {
		t.Error("Scanner engine should not be nil")
	}
	if scanner.Logger == nil {
		t.Error("Logger should not be nil")
	}
	if scanner.ErrorHandler == nil {
		t.Error("Error handler should not be nil")
	}
	if scanner.ResourceManager == nil {
		t.Error("Resource manager should not be nil")
	}
}

// TestComprehensiveScannerValidation tests the validation functionality
func TestComprehensiveScannerValidation(t *testing.T) {
	config := DefaultComprehensiveScannerConfig()
	config.LogToFile = false

	scanner, err := NewComprehensiveScanner(config)
	if err != nil {
		t.Fatalf("Failed to create comprehensive scanner: %v", err)
	}
	defer scanner.Close()

	// Test valid configuration
	validConfig := ScanConfig{
		Targets:    []string{"127.0.0.1"},
		Ports:      []int{80, 443},
		MaxThreads: 10,
		Timeout:    5 * time.Second,
		ScanType:   ScanTypeTCPConnect,
	}

	err = scanner.ValidateConfiguration(validConfig)
	if err != nil {
		t.Errorf("Valid configuration should not produce error: %v", err)
	}

	// Test invalid configuration
	invalidConfig := ScanConfig{
		Targets:    []string{}, // Empty targets
		Ports:      []int{80},
		MaxThreads: 10,
		Timeout:    5 * time.Second,
		ScanType:   ScanTypeTCPConnect,
	}

	err = scanner.ValidateConfiguration(invalidConfig)
	if err == nil {
		t.Error("Invalid configuration should produce error")
	}
}

// TestComprehensiveScannerResourceEstimation tests resource estimation
func TestComprehensiveScannerResourceEstimation(t *testing.T) {
	config := DefaultComprehensiveScannerConfig()
	config.LogToFile = false

	scanner, err := NewComprehensiveScanner(config)
	if err != nil {
		t.Fatalf("Failed to create comprehensive scanner: %v", err)
	}
	defer scanner.Close()

	scanConfig := ScanConfig{
		Targets:    []string{"127.0.0.1"},
		Ports:      []int{80, 443, 22},
		MaxThreads: 5,
		Timeout:    1 * time.Second,
		ScanType:   ScanTypeTCPConnect,
	}

	estimate, err := scanner.EstimateResourceRequirements(scanConfig)
	if err != nil {
		t.Errorf("Resource estimation should not fail: %v", err)
	}

	// Verify estimate makes sense
	if estimate.TotalOperations != 3 { // 1 target * 3 ports
		t.Errorf("Expected 3 total operations, got %d", estimate.TotalOperations)
	}

	if estimate.PeakConnections != 5 { // MaxThreads
		t.Errorf("Expected 5 peak connections, got %d", estimate.PeakConnections)
	}
}

// TestComprehensiveScannerErrorStatistics tests error statistics functionality
func TestComprehensiveScannerErrorStatistics(t *testing.T) {
	config := DefaultComprehensiveScannerConfig()
	config.LogToFile = false

	scanner, err := NewComprehensiveScanner(config)
	if err != nil {
		t.Fatalf("Failed to create comprehensive scanner: %v", err)
	}
	defer scanner.Close()

	// Get initial statistics
	stats := scanner.GetErrorStatistics()
	if stats.TotalErrors != 0 {
		t.Errorf("Expected 0 initial errors, got %d", stats.TotalErrors)
	}

	// Simulate an error by calling the error handler directly
	testErr := NewValidationError("test", "test error")
	scanner.ErrorHandler.HandleValidationError(testErr, "test_operation")

	// Check statistics updated
	stats = scanner.GetErrorStatistics()
	if stats.TotalErrors != 1 {
		t.Errorf("Expected 1 error after handling, got %d", stats.TotalErrors)
	}
}

// TestComprehensiveScannerResourceUsage tests resource usage monitoring
func TestComprehensiveScannerResourceUsage(t *testing.T) {
	config := DefaultComprehensiveScannerConfig()
	config.LogToFile = false

	scanner, err := NewComprehensiveScanner(config)
	if err != nil {
		t.Fatalf("Failed to create comprehensive scanner: %v", err)
	}
	defer scanner.Close()

	usage := scanner.GetResourceUsage()

	// Verify usage structure is populated
	if usage.Goroutines <= 0 {
		t.Error("Goroutine count should be positive")
	}

	if usage.MemoryMB < 0 {
		t.Error("Memory usage should not be negative")
	}

	if usage.StartTime.IsZero() {
		t.Error("Start time should be set")
	}
}

// TestDefaultComprehensiveScanner tests the default scanner creation
func TestDefaultComprehensiveScanner(t *testing.T) {
	scanner, err := CreateDefaultComprehensiveScanner()
	if err != nil {
		t.Fatalf("Failed to create default comprehensive scanner: %v", err)
	}
	defer scanner.Close()

	// Verify it's properly configured
	if scanner.Engine == nil {
		t.Error("Default scanner should have engine")
	}

	// Test a simple scan to make sure everything is wired up
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	scanConfig := ScanConfig{
		Targets:    []string{"127.0.0.1"},
		Ports:      []int{12345}, // Unlikely to be open
		MaxThreads: 1,
		Timeout:    100 * time.Millisecond,
		ScanType:   ScanTypeTCPConnect,
	}

	result, err := scanner.Engine.Scan(ctx, scanConfig)
	if err != nil {
		t.Errorf("Scan should not fail even with unreachable ports: %v", err)
	}

	if result == nil {
		t.Error("Scan result should not be nil")
	}

	if len(result.Hosts) != 1 {
		t.Errorf("Expected 1 host result, got %d", len(result.Hosts))
	}
}
