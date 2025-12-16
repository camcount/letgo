package networkmapper

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestScannerEngineIntegration tests the complete scanner engine integration
func TestScannerEngineIntegration(t *testing.T) {
	// Create real components
	logger := log.New(os.Stderr, "integration-test: ", log.LstdFlags)
	portScanner := NewDefaultPortScanner(100*time.Millisecond, 1, logger)
	targetResolver := NewTargetResolver()

	// Create scanner engine
	engine := NewConcurrentScannerEngine(
		portScanner,
		nil, // No service detector for basic test
		nil, // No OS fingerprinter for basic test
		targetResolver,
		nil, // No progress monitor for basic test
		logger,
	)

	// Create scan configuration
	config := ScanConfig{
		Targets:    []string{"127.0.0.1"},
		Ports:      []int{22, 80, 443}, // Common ports
		ScanType:   ScanTypeTCPConnect,
		MaxThreads: 5,
		Timeout:    1 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Perform scan
	result, err := engine.Scan(ctx, config)
	require.NoError(t, err, "Scan should complete successfully")
	require.NotNil(t, result, "Should return scan result")

	// Verify results
	require.Equal(t, 1, len(result.Hosts), "Should scan one host")
	require.Equal(t, "127.0.0.1", result.Hosts[0].Target, "Should scan localhost")
	require.Equal(t, 3, len(result.Hosts[0].Ports), "Should scan 3 ports")

	// Verify statistics
	require.Equal(t, 1, result.Statistics.HostsScanned, "Should have scanned 1 host")
	require.Equal(t, 3, result.Statistics.PortsScanned, "Should have scanned 3 ports")
	require.Greater(t, result.Statistics.ElapsedTime, time.Duration(0), "Should have elapsed time")

	// Verify scan configuration is preserved
	require.Equal(t, config.Targets, result.ScanConfig.Targets, "Should preserve targets")
	require.Equal(t, config.Ports, result.ScanConfig.Ports, "Should preserve ports")
	require.Equal(t, config.ScanType, result.ScanConfig.ScanType, "Should preserve scan type")
}

// TestScannerEngineWithPauseResume tests pause and resume functionality
func TestScannerEngineWithPauseResume(t *testing.T) {
	logger := log.New(os.Stderr, "pause-resume-test: ", log.LstdFlags)

	// Use mock scanner with longer delay to ensure we can pause
	mockScanner := NewMockPortScanner(200 * time.Millisecond)
	targetResolver := NewTargetResolver()

	engine := NewConcurrentScannerEngine(
		mockScanner,
		nil,
		nil,
		targetResolver,
		nil, // No progress monitor for this test
		logger,
	)

	config := ScanConfig{
		Targets:    []string{"127.0.0.1"},
		Ports:      []int{80, 443, 22, 21, 25, 53}, // More ports for longer scan
		ScanType:   ScanTypeTCPConnect,
		MaxThreads: 2,
		Timeout:    1 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Start scan in goroutine
	var result *ScanResult
	var scanErr error
	done := make(chan struct{})

	go func() {
		defer close(done)
		result, scanErr = engine.Scan(ctx, config)
	}()

	// Wait for scan to start
	time.Sleep(100 * time.Millisecond)

	// Pause the scan
	err := engine.Pause()
	require.NoError(t, err, "Should be able to pause scan")

	// Wait while paused
	time.Sleep(300 * time.Millisecond)

	// Resume the scan
	err = engine.Resume()
	require.NoError(t, err, "Should be able to resume scan")

	// Wait for completion
	<-done

	// Verify scan completed successfully
	require.NoError(t, scanErr, "Scan should complete after resume")
	require.NotNil(t, result, "Should return result")
	require.Equal(t, 1, len(result.Hosts), "Should scan one host")
	require.Equal(t, 6, len(result.Hosts[0].Ports), "Should scan all ports")
}

// TestScannerEngineConnectionLimiting tests connection limiting
func TestScannerEngineConnectionLimiting(t *testing.T) {
	logger := log.New(os.Stderr, "connection-limit-test: ", log.LstdFlags)

	// Use mock scanner to track connections
	mockScanner := NewMockPortScanner(50 * time.Millisecond)
	targetResolver := NewTargetResolver()

	engine := NewConcurrentScannerEngine(
		mockScanner,
		nil,
		nil,
		targetResolver,
		nil, // No progress monitor for this test
		logger,
	)

	config := ScanConfig{
		Targets:    []string{"127.0.0.1"},
		Ports:      []int{80, 443, 22, 21, 25, 53, 110, 143, 993, 995}, // 10 ports
		ScanType:   ScanTypeTCPConnect,
		MaxThreads: 3, // Limit to 3 concurrent connections
		Timeout:    1 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Reset mock scanner
	mockScanner.Reset()

	// Perform scan
	result, err := engine.Scan(ctx, config)
	require.NoError(t, err, "Scan should complete successfully")
	require.NotNil(t, result, "Should return result")

	// Verify connection limit was respected
	maxObserved := mockScanner.GetMaxObservedConnections()
	require.LessOrEqual(t, maxObserved, int64(3),
		"Should not exceed connection limit of 3, observed: %d", maxObserved)

	// Verify all ports were scanned
	require.Equal(t, 10, len(result.Hosts[0].Ports), "Should scan all 10 ports")
}
