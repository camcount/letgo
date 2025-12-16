package networkmapper

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// MockProgressMonitor for testing progress reporting
type MockProgressMonitor struct {
	progressUpdates []ProgressInfo
	mutex           sync.RWMutex
	isStarted       bool
	isStopped       bool
}

func NewMockProgressMonitor() *MockProgressMonitor {
	return &MockProgressMonitor{
		progressUpdates: make([]ProgressInfo, 0),
	}
}

func (m *MockProgressMonitor) Start(totalHosts, totalPorts int) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.isStarted = true
	m.isStopped = false
}

func (m *MockProgressMonitor) UpdateProgress(hostsScanned, portsScanned int, currentTarget string, currentPort int) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if !m.isStarted || m.isStopped {
		return
	}

	progress := ProgressInfo{
		HostsScanned:  hostsScanned,
		PortsScanned:  portsScanned,
		CurrentTarget: currentTarget,
		CurrentPort:   currentPort,
		ElapsedTime:   time.Since(time.Now().Add(-time.Duration(len(m.progressUpdates)) * 100 * time.Millisecond)),
	}

	m.progressUpdates = append(m.progressUpdates, progress)
}

func (m *MockProgressMonitor) Stop() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.isStopped = true
}

func (m *MockProgressMonitor) GetProgress() ProgressInfo {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if len(m.progressUpdates) == 0 {
		return ProgressInfo{}
	}

	return m.progressUpdates[len(m.progressUpdates)-1]
}

func (m *MockProgressMonitor) GetProgressUpdates() []ProgressInfo {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	updates := make([]ProgressInfo, len(m.progressUpdates))
	copy(updates, m.progressUpdates)
	return updates
}

func (m *MockProgressMonitor) IsStarted() bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.isStarted
}

func (m *MockProgressMonitor) IsStopped() bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.isStopped
}

// **Feature: network-mapper, Property 6: Progress Reporting**
// **Validates: Requirements 2.4, 8.1, 8.2**
// Property: For any scanning operation, real-time progress updates should be provided
// including completion percentage and estimated time remaining
func TestProperty6_ProgressReporting(t *testing.T) {
	// Property-based test with 100 iterations as specified in design
	for i := range 100 {
		t.Run(fmt.Sprintf("iteration_%d", i), func(t *testing.T) {
			// Generate random scan parameters
			numTargets := rand.Intn(3) + 1 // 1-3 targets
			numPorts := rand.Intn(10) + 5  // 5-14 ports per target

			// Create mock components
			mockScanner := NewMockPortScanner(50 * time.Millisecond) // Short delay for faster tests
			mockResolver := &MockTargetResolver{}
			mockProgressMonitor := NewMockProgressMonitor()
			logger := log.New(os.Stderr, "test: ", log.LstdFlags)

			// Create scanner engine with progress monitor
			engine := NewConcurrentScannerEngine(
				mockScanner,
				nil, // No service detector needed for this test
				nil, // No OS fingerprinter needed for this test
				mockResolver,
				mockProgressMonitor,
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

			// Create scan config
			config := ScanConfig{
				Targets:    targets,
				Ports:      ports,
				ScanType:   ScanTypeTCPConnect,
				MaxThreads: 5,
				Timeout:    1 * time.Second,
			}

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			// Perform scan
			result, err := engine.Scan(ctx, config)
			require.NoError(t, err, "Scan should complete successfully")
			require.NotNil(t, result, "Should return scan result")

			// Verify progress monitor was started (Requirements 2.4, 8.1, 8.2)
			require.True(t, mockProgressMonitor.IsStarted(),
				"Progress monitor should be started during scan")

			// Verify progress monitor was stopped
			require.True(t, mockProgressMonitor.IsStopped(),
				"Progress monitor should be stopped after scan completion")

			// Verify progress updates were provided (Requirements 2.4, 8.1, 8.2)
			progressUpdates := mockProgressMonitor.GetProgressUpdates()
			require.Greater(t, len(progressUpdates), 0,
				"Should provide real-time progress updates during scan")

			// Verify progress information completeness
			if len(progressUpdates) > 0 {
				lastProgress := progressUpdates[len(progressUpdates)-1]

				// Verify hosts scanned count is reasonable
				require.GreaterOrEqual(t, lastProgress.HostsScanned, 0,
					"Hosts scanned should be non-negative")
				require.LessOrEqual(t, lastProgress.HostsScanned, numTargets,
					"Hosts scanned should not exceed total targets")

				// Verify ports scanned count is reasonable
				require.GreaterOrEqual(t, lastProgress.PortsScanned, 0,
					"Ports scanned should be non-negative")
				totalPorts := numTargets * numPorts
				require.LessOrEqual(t, lastProgress.PortsScanned, totalPorts,
					"Ports scanned should not exceed total ports")

				// Verify elapsed time is recorded (Requirements 8.1, 8.2)
				require.GreaterOrEqual(t, lastProgress.ElapsedTime, time.Duration(0),
					"Elapsed time should be non-negative")

				// Verify current target information is provided when available
				if lastProgress.CurrentTarget != "" {
					// Current target could be either the original target name or resolved IP
					isValidTarget := false
					for _, target := range targets {
						if lastProgress.CurrentTarget == target || lastProgress.CurrentTarget == "127.0.0.1" {
							isValidTarget = true
							break
						}
					}
					require.True(t, isValidTarget,
						"Current target '%s' should be one of the scan targets %v or resolved IP",
						lastProgress.CurrentTarget, targets)
				}

				// Verify current port information is provided when available
				if lastProgress.CurrentPort > 0 {
					require.Contains(t, ports, lastProgress.CurrentPort,
						"Current port should be one of the scan ports")
				}
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

// Test progress monitor lifecycle
func TestProgressMonitorLifecycle(t *testing.T) {
	mockProgressMonitor := NewMockProgressMonitor()

	// Initially not started or stopped
	require.False(t, mockProgressMonitor.IsStarted(), "Should not be started initially")
	require.False(t, mockProgressMonitor.IsStopped(), "Should not be stopped initially")

	// Start monitoring
	mockProgressMonitor.Start(5, 50)
	require.True(t, mockProgressMonitor.IsStarted(), "Should be started after Start()")
	require.False(t, mockProgressMonitor.IsStopped(), "Should not be stopped after Start()")

	// Update progress
	mockProgressMonitor.UpdateProgress(2, 20, "target1", 80)
	progress := mockProgressMonitor.GetProgress()
	require.Equal(t, 2, progress.HostsScanned, "Should track hosts scanned")
	require.Equal(t, 20, progress.PortsScanned, "Should track ports scanned")
	require.Equal(t, "target1", progress.CurrentTarget, "Should track current target")
	require.Equal(t, 80, progress.CurrentPort, "Should track current port")

	// Stop monitoring
	mockProgressMonitor.Stop()
	require.True(t, mockProgressMonitor.IsStarted(), "Should still be marked as started")
	require.True(t, mockProgressMonitor.IsStopped(), "Should be stopped after Stop()")
}

// Test progress updates during scan
func TestProgressUpdatesDuringScan(t *testing.T) {
	mockScanner := NewMockPortScanner(100 * time.Millisecond)
	mockResolver := &MockTargetResolver{}
	mockProgressMonitor := NewMockProgressMonitor()
	logger := log.New(os.Stderr, "test: ", log.LstdFlags)

	engine := NewConcurrentScannerEngine(
		mockScanner,
		nil,
		nil,
		mockResolver,
		mockProgressMonitor,
		logger,
	)

	config := ScanConfig{
		Targets:    []string{"target1", "target2"},
		Ports:      []int{80, 443, 22},
		ScanType:   ScanTypeTCPConnect,
		MaxThreads: 2,
		Timeout:    1 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Perform scan
	result, err := engine.Scan(ctx, config)
	require.NoError(t, err, "Scan should complete successfully")
	require.NotNil(t, result, "Should return scan result")

	// Verify progress updates were received
	progressUpdates := mockProgressMonitor.GetProgressUpdates()
	require.Greater(t, len(progressUpdates), 0, "Should receive progress updates")

	// Verify progress updates show increasing values
	if len(progressUpdates) > 1 {
		firstUpdate := progressUpdates[0]
		lastUpdate := progressUpdates[len(progressUpdates)-1]

		require.GreaterOrEqual(t, lastUpdate.HostsScanned, firstUpdate.HostsScanned,
			"Hosts scanned should not decrease")
		require.GreaterOrEqual(t, lastUpdate.PortsScanned, firstUpdate.PortsScanned,
			"Ports scanned should not decrease")
	}
}

// Test DefaultProgressMonitor implementation
func TestDefaultProgressMonitor(t *testing.T) {
	var progressUpdates []ProgressInfo
	var mutex sync.Mutex

	// Create callback to capture progress updates
	progressCallback := func(progress ProgressInfo) {
		mutex.Lock()
		defer mutex.Unlock()
		progressUpdates = append(progressUpdates, progress)
	}

	monitor := NewDefaultProgressMonitor(progressCallback)

	// Start monitoring
	monitor.Start(3, 30)

	// Simulate progress updates
	monitor.UpdateProgress(1, 10, "target1", 80)
	monitor.UpdateProgress(2, 20, "target2", 443)
	monitor.UpdateProgress(3, 30, "target3", 22)

	// Stop monitoring
	monitor.Stop()

	// Verify progress updates were captured
	mutex.Lock()
	defer mutex.Unlock()

	require.Greater(t, len(progressUpdates), 0, "Should capture progress updates")

	// Verify final progress
	finalProgress := monitor.GetProgress()
	require.Equal(t, 3, finalProgress.HostsScanned, "Should track final hosts scanned")
	require.Equal(t, 30, finalProgress.PortsScanned, "Should track final ports scanned")
	require.Equal(t, "target3", finalProgress.CurrentTarget, "Should track final target")
	require.Equal(t, 22, finalProgress.CurrentPort, "Should track final port")
}

// Test progress calculation accuracy
func TestProgressCalculationAccuracy(t *testing.T) {
	monitor := NewDefaultProgressMonitor(nil)

	// Start with known totals
	totalHosts := 5
	totalPorts := 50
	monitor.Start(totalHosts, totalPorts)

	// Update progress
	hostsScanned := 3
	portsScanned := 30
	monitor.UpdateProgress(hostsScanned, portsScanned, "target3", 80)

	progress := monitor.GetProgress()

	// Verify calculations
	require.Equal(t, totalHosts, progress.HostsTotal, "Should track total hosts")
	require.Equal(t, totalPorts, progress.PortsTotal, "Should track total ports")
	require.Equal(t, hostsScanned, progress.HostsScanned, "Should track scanned hosts")
	require.Equal(t, portsScanned, progress.PortsScanned, "Should track scanned ports")

	// Verify scan rate calculation
	if progress.ElapsedTime.Seconds() > 0 {
		expectedRate := float64(portsScanned) / progress.ElapsedTime.Seconds()
		require.InDelta(t, expectedRate, progress.ScanRate, 0.1,
			"Scan rate should be calculated correctly")
	}

	// Verify ETA calculation
	if progress.ScanRate > 0 {
		remaining := totalPorts - portsScanned
		expectedETA := time.Duration(float64(remaining)/progress.ScanRate) * time.Second
		require.InDelta(t, expectedETA.Seconds(), progress.EstimatedTime.Seconds(), 1.0,
			"ETA should be calculated correctly")
	}
}

// Test console progress display
func TestConsoleProgressDisplay(t *testing.T) {
	monitor := NewDefaultProgressMonitor(nil)
	display := NewConsoleProgressDisplay(monitor)

	// Test progress display with sample data
	progress := ProgressInfo{
		HostsScanned:  2,
		HostsTotal:    5,
		PortsScanned:  150,
		PortsTotal:    500,
		ElapsedTime:   2 * time.Minute,
		EstimatedTime: 3 * time.Minute,
		ScanRate:      1.25,
		CurrentTarget: "192.168.1.1",
		CurrentPort:   443,
	}

	// This should not panic or error
	require.NotPanics(t, func() {
		display.DisplayProgress(progress)
		display.Finish()
	}, "Console display should handle progress updates without panicking")
}

// Test progress bar rendering
func TestProgressBarRendering(t *testing.T) {
	progressBar := NewProgressBarDisplay(20) // 20 character width

	tests := []struct {
		name    string
		percent float64
		want    string
	}{
		{
			name:    "0 percent",
			percent: 0.0,
			want:    "[                    ] 0.0%",
		},
		{
			name:    "50 percent",
			percent: 50.0,
			want:    "[==========          ] 50.0%",
		},
		{
			name:    "100 percent",
			percent: 100.0,
			want:    "[====================] 100.0%",
		},
		{
			name:    "over 100 percent",
			percent: 150.0,
			want:    "[====================] 100.0%",
		},
		{
			name:    "negative percent",
			percent: -10.0,
			want:    "[                    ] 0.0%",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := progressBar.RenderProgressBar(tt.percent)
			require.Equal(t, tt.want, result, "Progress bar should render correctly")
		})
	}
}

// Test combined progress display
func TestCombinedProgressDisplay(t *testing.T) {
	var updates1, updates2 []ProgressInfo
	var mutex1, mutex2 sync.Mutex

	callback1 := func(progress ProgressInfo) {
		mutex1.Lock()
		defer mutex1.Unlock()
		updates1 = append(updates1, progress)
	}

	callback2 := func(progress ProgressInfo) {
		mutex2.Lock()
		defer mutex2.Unlock()
		updates2 = append(updates2, progress)
	}

	combined := NewCombinedProgressDisplay(callback1, callback2)

	progress := ProgressInfo{
		HostsScanned: 1,
		PortsScanned: 10,
	}

	// Send progress update to combined display
	combined.DisplayProgress(progress)

	// Verify both callbacks received the update
	mutex1.Lock()
	require.Equal(t, 1, len(updates1), "First callback should receive update")
	require.Equal(t, 1, updates1[0].HostsScanned, "First callback should receive correct data")
	mutex1.Unlock()

	mutex2.Lock()
	require.Equal(t, 1, len(updates2), "Second callback should receive update")
	require.Equal(t, 1, updates2[0].HostsScanned, "Second callback should receive correct data")
	mutex2.Unlock()
}

// Test duration formatting
func TestDurationFormatting(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		want     string
	}{
		{
			name:     "zero duration",
			duration: 0,
			want:     "0s",
		},
		{
			name:     "seconds only",
			duration: 45 * time.Second,
			want:     "45s",
		},
		{
			name:     "minutes and seconds",
			duration: 2*time.Minute + 30*time.Second,
			want:     "2m30s",
		},
		{
			name:     "hours, minutes, and seconds",
			duration: 1*time.Hour + 23*time.Minute + 45*time.Second,
			want:     "1h23m45s",
		},
		{
			name:     "sub-second duration",
			duration: 500 * time.Millisecond,
			want:     "0s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatDuration(tt.duration)
			require.Equal(t, tt.want, result, "Duration should be formatted correctly")
		})
	}
}
