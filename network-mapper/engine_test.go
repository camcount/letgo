package networkmapper

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// MockPortScanner for testing that tracks concurrent connections
type MockPortScanner struct {
	activeConnections int64
	maxObserved       int64
	mutex             sync.Mutex
	scanDelay         time.Duration
}

func NewMockPortScanner(scanDelay time.Duration) *MockPortScanner {
	return &MockPortScanner{
		scanDelay: scanDelay,
	}
}

func (m *MockPortScanner) ScanPort(ctx context.Context, target string, port int, scanType ScanType) PortResult {
	// Track connection start
	current := atomic.AddInt64(&m.activeConnections, 1)

	// Update max observed connections
	m.mutex.Lock()
	if current > m.maxObserved {
		m.maxObserved = current
	}
	m.mutex.Unlock()

	// Simulate scan delay
	select {
	case <-time.After(m.scanDelay):
	case <-ctx.Done():
	}

	// Track connection end
	atomic.AddInt64(&m.activeConnections, -1)

	return PortResult{
		Port:         port,
		Protocol:     getProtocolForScanType(scanType),
		State:        PortClosed, // Always return closed for testing
		ResponseTime: m.scanDelay,
	}
}

func (m *MockPortScanner) ScanPorts(ctx context.Context, target string, ports []int, scanType ScanType) []PortResult {
	results := make([]PortResult, len(ports))
	for i, port := range ports {
		results[i] = m.ScanPort(ctx, target, port, scanType)
	}
	return results
}

func (m *MockPortScanner) GetMaxObservedConnections() int64 {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.maxObserved
}

func (m *MockPortScanner) Reset() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	atomic.StoreInt64(&m.activeConnections, 0)
	m.maxObserved = 0
}

// MockTargetResolver for testing
type MockTargetResolver struct{}

func (m *MockTargetResolver) ResolveTargets(targets []string) ([]NetworkTarget, error) {
	resolved := make([]NetworkTarget, len(targets))
	for i, target := range targets {
		resolved[i] = NetworkTarget{
			Original: target,
			IPs:      []net.IP{net.ParseIP("127.0.0.1")}, // Always resolve to localhost
		}
	}
	return resolved, nil
}

func (m *MockTargetResolver) ExpandCIDR(cidr string) ([]string, error) {
	return []string{"127.0.0.1"}, nil
}

func (m *MockTargetResolver) ResolveHostname(hostname string) ([]string, error) {
	return []string{"127.0.0.1"}, nil
}

// **Feature: network-mapper, Property 5: Connection Limiting**
// **Validates: Requirements 2.3**
// Property: For any concurrent scanning operation, the number of simultaneous connections
// should never exceed the specified maximum limit
func TestProperty5_ConnectionLimiting(t *testing.T) {
	// Property-based test with 100 iterations as specified in design
	for i := range 100 {
		t.Run(fmt.Sprintf("iteration_%d", i), func(t *testing.T) {
			// Generate random connection limit (1-50 to keep tests reasonable)
			maxConnections := rand.Intn(49) + 1

			// Generate random number of targets and ports
			numTargets := rand.Intn(5) + 1 // 1-5 targets
			numPorts := rand.Intn(20) + 5  // 5-24 ports per target

			// Create mock components with delay to ensure concurrency
			mockScanner := NewMockPortScanner(50 * time.Millisecond) // 50ms delay per scan
			mockResolver := &MockTargetResolver{}
			logger := log.New(os.Stderr, "test: ", log.LstdFlags)

			// Create scanner engine
			engine := NewConcurrentScannerEngine(
				mockScanner,
				nil, // No service detector needed for this test
				nil, // No OS fingerprinter needed for this test
				mockResolver,
				nil, // No progress monitor needed for this test
				nil, // No IP resolver needed for this test
				nil, // No protection detector needed for this test
				nil, // No infrastructure analyzer needed for this test
				logger,
			)

			// Generate targets and ports
			targets := make([]string, numTargets)
			for j := 0; j < numTargets; j++ {
				targets[j] = fmt.Sprintf("target%d", j)
			}

			ports := make([]int, numPorts)
			for j := 0; j < numPorts; j++ {
				ports[j] = 1000 + j
			}

			// Create scan config with connection limit
			config := ScanConfig{
				Targets:    targets,
				Ports:      ports,
				ScanType:   ScanTypeTCPConnect,
				MaxThreads: maxConnections,
				Timeout:    1 * time.Second,
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Reset mock scanner counters
			mockScanner.Reset()

			// Perform scan
			result, err := engine.Scan(ctx, config)
			require.NoError(t, err, "Scan should complete successfully")
			require.NotNil(t, result, "Should return scan result")

			// Verify that the maximum observed connections never exceeded the limit
			maxObserved := mockScanner.GetMaxObservedConnections()
			require.LessOrEqual(t, maxObserved, int64(maxConnections),
				"Maximum observed connections (%d) should not exceed limit (%d)",
				maxObserved, maxConnections)

			// Verify that we actually used concurrency (if we have enough work and limit > 1)
			totalWork := numTargets * numPorts
			if totalWork > maxConnections && maxConnections > 1 {
				require.Greater(t, maxObserved, int64(1),
					"Should use concurrent connections when work exceeds limit and limit > 1")
			}

			// Verify scan completed all work
			require.Equal(t, numTargets, len(result.Hosts),
				"Should scan all %d targets", numTargets)

			for _, host := range result.Hosts {
				require.Equal(t, numPorts, len(host.Ports),
					"Should scan all %d ports for each host", numPorts)
			}
		})
	}
}

// **Feature: network-mapper, Property 18: Scan Control Operations**
// **Validates: Requirements 8.3, 8.4**
// Property: For any running scan, pause, resume, and stop operations should function
// correctly with appropriate state management
func TestProperty18_ScanControlOperations(t *testing.T) {
	// Property-based test with 100 iterations as specified in design
	for i := range 100 {
		t.Run(fmt.Sprintf("iteration_%d", i), func(t *testing.T) {
			// Generate random scan parameters
			numTargets := rand.Intn(3) + 1 // 1-3 targets
			numPorts := rand.Intn(10) + 5  // 5-14 ports

			mockScanner := NewMockPortScanner(100 * time.Millisecond) // Longer delay for control testing
			mockResolver := &MockTargetResolver{}
			logger := log.New(os.Stderr, "test: ", log.LstdFlags)

			engine := NewConcurrentScannerEngine(
				mockScanner,
				nil,
				nil,
				mockResolver,
				nil, // No progress monitor needed for this test
				nil, // No IP resolver needed for this test
				nil, // No protection detector needed for this test
				nil, // No infrastructure analyzer needed for this test
				logger,
			)

			targets := make([]string, numTargets)
			for j := 0; j < numTargets; j++ {
				targets[j] = fmt.Sprintf("target%d", j)
			}

			ports := make([]int, numPorts)
			for j := 0; j < numPorts; j++ {
				ports[j] = 1000 + j
			}

			config := ScanConfig{
				Targets:    targets,
				Ports:      ports,
				ScanType:   ScanTypeTCPConnect,
				MaxThreads: 5,
				Timeout:    1 * time.Second,
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Test different control operations randomly
			controlOp := rand.Intn(3) // 0=pause/resume, 1=stop, 2=no control

			switch controlOp {
			case 0: // Test pause and resume
				var wg sync.WaitGroup
				wg.Add(1)

				go func() {
					defer wg.Done()
					result, err := engine.Scan(ctx, config)
					if err == nil {
						require.NotNil(t, result, "Should return result if scan completes")
					}
				}()

				// Wait a bit for scan to start
				time.Sleep(50 * time.Millisecond)

				// Test pause
				err := engine.Pause()
				if err == nil {
					// Verify state is paused
					progress := engine.GetProgress()
					require.Greater(t, progress.ElapsedTime, time.Duration(0),
						"Should have some elapsed time when paused")

					// Wait a bit while paused
					time.Sleep(100 * time.Millisecond)

					// Test resume (only if still paused - scan might have completed)
					err = engine.Resume()
					if err != nil && !strings.Contains(err.Error(), "idle") {
						require.NoError(t, err, "Should be able to resume paused scan")
					}
				}

				wg.Wait()

			case 1: // Test stop
				var wg sync.WaitGroup
				wg.Add(1)

				go func() {
					defer wg.Done()
					_, _ = engine.Scan(ctx, config) // May return error due to stop
				}()

				// Wait a bit for scan to start
				time.Sleep(50 * time.Millisecond)

				// Test stop
				err := engine.Stop()
				require.NoError(t, err, "Should be able to stop running scan")

				wg.Wait()

			case 2: // No control operations, just run normally
				result, err := engine.Scan(ctx, config)
				require.NoError(t, err, "Normal scan should complete successfully")
				require.NotNil(t, result, "Should return scan result")
				require.Equal(t, numTargets, len(result.Hosts),
					"Should scan all targets")
			}
		})
	}
}

// Test connection limiting with edge cases
func TestConnectionLimitingEdgeCases(t *testing.T) {
	tests := []struct {
		name           string
		maxConnections int
		numTargets     int
		numPorts       int
	}{
		{
			name:           "single connection limit",
			maxConnections: 1,
			numTargets:     3,
			numPorts:       5,
		},
		{
			name:           "limit equals work",
			maxConnections: 10,
			numTargets:     2,
			numPorts:       5, // 2*5 = 10 total work
		},
		{
			name:           "limit exceeds work",
			maxConnections: 100,
			numTargets:     2,
			numPorts:       3, // 2*3 = 6 total work
		},
		{
			name:           "high concurrency",
			maxConnections: 50,
			numTargets:     5,
			numPorts:       20, // 5*20 = 100 total work
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockScanner := NewMockPortScanner(10 * time.Millisecond)
			mockResolver := &MockTargetResolver{}
			logger := log.New(os.Stderr, "test: ", log.LstdFlags)

			engine := NewConcurrentScannerEngine(
				mockScanner,
				nil,
				nil,
				mockResolver,
				nil, // No progress monitor needed for this test
				nil, // No IP resolver needed for this test
				nil, // No protection detector needed for this test
				nil, // No infrastructure analyzer needed for this test
				logger,
			)

			targets := make([]string, tt.numTargets)
			for i := 0; i < tt.numTargets; i++ {
				targets[i] = fmt.Sprintf("target%d", i)
			}

			ports := make([]int, tt.numPorts)
			for i := 0; i < tt.numPorts; i++ {
				ports[i] = 1000 + i
			}

			config := ScanConfig{
				Targets:    targets,
				Ports:      ports,
				ScanType:   ScanTypeTCPConnect,
				MaxThreads: tt.maxConnections,
				Timeout:    1 * time.Second,
			}

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			mockScanner.Reset()

			result, err := engine.Scan(ctx, config)
			require.NoError(t, err, "Scan should complete successfully")

			maxObserved := mockScanner.GetMaxObservedConnections()
			require.LessOrEqual(t, maxObserved, int64(tt.maxConnections),
				"Should respect connection limit of %d", tt.maxConnections)

			// Verify all work was completed
			require.Equal(t, tt.numTargets, len(result.Hosts),
				"Should complete all targets")
		})
	}
}

// Test that default connection limit is applied when not specified
func TestDefaultConnectionLimit(t *testing.T) {
	mockScanner := NewMockPortScanner(10 * time.Millisecond)
	mockResolver := &MockTargetResolver{}
	logger := log.New(os.Stderr, "test: ", log.LstdFlags)

	engine := NewConcurrentScannerEngine(
		mockScanner,
		nil,
		nil,
		mockResolver,
		nil, // No progress monitor needed for this test
		nil, // No IP resolver needed for this test
		nil, // No protection detector needed for this test
		nil, // No infrastructure analyzer needed for this test
		logger,
	)

	config := ScanConfig{
		Targets:    []string{"target1", "target2"},
		Ports:      []int{80, 443, 22, 21, 25},
		ScanType:   ScanTypeTCPConnect,
		MaxThreads: 0, // No limit specified, should use default
		Timeout:    1 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mockScanner.Reset()

	result, err := engine.Scan(ctx, config)
	require.NoError(t, err, "Scan should complete successfully")

	maxObserved := mockScanner.GetMaxObservedConnections()
	require.LessOrEqual(t, maxObserved, int64(100), // Default limit is 100
		"Should respect default connection limit")

	require.Equal(t, 2, len(result.Hosts), "Should scan all targets")
}

// Test scan state management
func TestScanStateManagement(t *testing.T) {
	mockScanner := NewMockPortScanner(50 * time.Millisecond)
	mockResolver := &MockTargetResolver{}
	logger := log.New(os.Stderr, "test: ", log.LstdFlags)

	engine := NewConcurrentScannerEngine(
		mockScanner,
		nil,
		nil,
		mockResolver,
		nil, // No progress monitor needed for this test
		nil, // No IP resolver needed for this test
		nil, // No protection detector needed for this test
		nil, // No infrastructure analyzer needed for this test
		logger,
	)

	// Initially should be idle
	require.Equal(t, ScanStateIdle, engine.state)

	// Should not be able to pause/resume/stop when idle
	err := engine.Pause()
	require.Error(t, err, "Should not be able to pause idle scanner")

	err = engine.Resume()
	require.Error(t, err, "Should not be able to resume idle scanner")

	err = engine.Stop()
	require.Error(t, err, "Should not be able to stop idle scanner")
}

// Test pause and resume functionality
func TestPauseResumeFunctionality(t *testing.T) {
	mockScanner := NewMockPortScanner(100 * time.Millisecond)
	mockResolver := &MockTargetResolver{}
	logger := log.New(os.Stderr, "test: ", log.LstdFlags)

	engine := NewConcurrentScannerEngine(
		mockScanner,
		nil,
		nil,
		mockResolver,
		nil, // No progress monitor needed for this test
		nil, // No IP resolver needed for this test
		nil, // No protection detector needed for this test
		nil, // No infrastructure analyzer needed for this test
		logger,
	)

	config := ScanConfig{
		Targets:    []string{"target1", "target2"},
		Ports:      []int{80, 443, 22, 21, 25, 53, 110, 143},
		ScanType:   ScanTypeTCPConnect,
		MaxThreads: 2,
		Timeout:    1 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	var scanResult *ScanResult
	var scanError error
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		scanResult, scanError = engine.Scan(ctx, config)
	}()

	// Wait for scan to start
	time.Sleep(50 * time.Millisecond)

	// Pause the scan
	err := engine.Pause()
	require.NoError(t, err, "Should be able to pause running scan")

	// Get progress while paused
	progress1 := engine.GetProgress()

	// Wait a bit while paused
	time.Sleep(200 * time.Millisecond)

	// Progress should not advance significantly while paused
	progress2 := engine.GetProgress()
	// Allow some tolerance for timing issues - scans in progress may complete
	require.LessOrEqual(t, progress2.PortsScanned-progress1.PortsScanned, 5,
		"Progress should not advance much while paused")

	// Resume the scan
	err = engine.Resume()
	require.NoError(t, err, "Should be able to resume paused scan")

	// Wait for scan to complete
	wg.Wait()

	// Scan should complete successfully
	require.NoError(t, scanError, "Resumed scan should complete successfully")
	require.NotNil(t, scanResult, "Should return scan result")
}

// Test stop functionality
func TestStopFunctionality(t *testing.T) {
	mockScanner := NewMockPortScanner(200 * time.Millisecond) // Longer delay
	mockResolver := &MockTargetResolver{}
	logger := log.New(os.Stderr, "test: ", log.LstdFlags)

	engine := NewConcurrentScannerEngine(
		mockScanner,
		nil,
		nil,
		mockResolver,
		nil, // No progress monitor needed for this test
		nil, // No IP resolver needed for this test
		nil, // No protection detector needed for this test
		nil, // No infrastructure analyzer needed for this test
		logger,
	)

	config := ScanConfig{
		Targets:    []string{"target1", "target2", "target3"},
		Ports:      []int{80, 443, 22, 21, 25, 53, 110, 143, 993, 995},
		ScanType:   ScanTypeTCPConnect,
		MaxThreads: 2,
		Timeout:    1 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = engine.Scan(ctx, config) // May return error due to stop
	}()

	// Wait for scan to start
	time.Sleep(100 * time.Millisecond)

	// Get progress before stopping
	progressBefore := engine.GetProgress()
	require.Greater(t, progressBefore.ElapsedTime, time.Duration(0),
		"Should have some progress before stopping")

	// Stop the scan
	err := engine.Stop()
	require.NoError(t, err, "Should be able to stop running scan")

	// Wait for scan goroutine to finish
	wg.Wait()

	// Should not be able to pause or resume after stop
	err = engine.Pause()
	require.Error(t, err, "Should not be able to pause stopped scanner")

	err = engine.Resume()
	require.Error(t, err, "Should not be able to resume stopped scanner")
}

// Test concurrent scan attempts (should fail)
func TestConcurrentScanAttempts(t *testing.T) {
	mockScanner := NewMockPortScanner(100 * time.Millisecond)
	mockResolver := &MockTargetResolver{}
	logger := log.New(os.Stderr, "test: ", log.LstdFlags)

	engine := NewConcurrentScannerEngine(
		mockScanner,
		nil,
		nil,
		mockResolver,
		nil, // No progress monitor needed for this test
		nil, // No IP resolver needed for this test
		nil, // No protection detector needed for this test
		nil, // No infrastructure analyzer needed for this test
		logger,
	)

	config := ScanConfig{
		Targets:    []string{"target1"},
		Ports:      []int{80, 443},
		ScanType:   ScanTypeTCPConnect,
		MaxThreads: 2,
		Timeout:    1 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup

	// Start first scan
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = engine.Scan(ctx, config)
	}()

	// Wait for first scan to start
	time.Sleep(50 * time.Millisecond)

	// Try to start second scan (should fail)
	_, err := engine.Scan(ctx, config)
	require.Error(t, err, "Should not be able to start concurrent scans")
	require.Contains(t, err.Error(), "already running",
		"Error should indicate scanner is already running")

	wg.Wait()
}
