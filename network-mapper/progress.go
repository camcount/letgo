package networkmapper

import (
	"fmt"
	"sync"
	"time"
)

// DefaultProgressMonitor implements the ProgressMonitor interface
type DefaultProgressMonitor struct {
	// Progress tracking
	totalHosts    int
	totalPorts    int
	hostsScanned  int
	portsScanned  int
	currentTarget string
	currentPort   int

	// Timing
	startTime      time.Time
	lastUpdateTime time.Time

	// Thread safety
	mutex sync.RWMutex

	// State
	isRunning bool

	// Callbacks
	onProgress ProgressCallback

	// Display settings
	displayInterval time.Duration
	lastDisplay     time.Time
}

// NewDefaultProgressMonitor creates a new progress monitor
func NewDefaultProgressMonitor(onProgress ProgressCallback) *DefaultProgressMonitor {
	return &DefaultProgressMonitor{
		onProgress:      onProgress,
		displayInterval: 1 * time.Second, // Update display every second
	}
}

// Start begins progress monitoring (Requirements 2.4, 8.1, 8.2)
func (pm *DefaultProgressMonitor) Start(totalHosts, totalPorts int) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.totalHosts = totalHosts
	pm.totalPorts = totalPorts
	pm.hostsScanned = 0
	pm.portsScanned = 0
	pm.currentTarget = ""
	pm.currentPort = 0
	pm.startTime = time.Now()
	pm.lastUpdateTime = pm.startTime
	pm.lastDisplay = pm.startTime
	pm.isRunning = true
}

// UpdateProgress updates the current progress (Requirements 2.4, 8.1, 8.2)
func (pm *DefaultProgressMonitor) UpdateProgress(hostsScanned, portsScanned int, currentTarget string, currentPort int) {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	if !pm.isRunning {
		return
	}

	pm.hostsScanned = hostsScanned
	pm.portsScanned = portsScanned
	pm.currentTarget = currentTarget
	pm.currentPort = currentPort
	pm.lastUpdateTime = time.Now()

	// Call progress callback if provided and enough time has passed
	if pm.onProgress != nil && time.Since(pm.lastDisplay) >= pm.displayInterval {
		pm.lastDisplay = time.Now()
		progress := pm.calculateProgress()
		pm.onProgress(progress)
	}
}

// Stop ends progress monitoring
func (pm *DefaultProgressMonitor) Stop() {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()

	pm.isRunning = false

	// Send final progress update
	if pm.onProgress != nil {
		progress := pm.calculateProgress()
		pm.onProgress(progress)
	}
}

// GetProgress returns current progress information (Requirements 2.4, 8.1, 8.2)
func (pm *DefaultProgressMonitor) GetProgress() ProgressInfo {
	pm.mutex.RLock()
	defer pm.mutex.RUnlock()

	return pm.calculateProgress()
}

// calculateProgress calculates the current progress information
// This method assumes the mutex is already held
func (pm *DefaultProgressMonitor) calculateProgress() ProgressInfo {
	now := time.Now()
	elapsed := now.Sub(pm.startTime)

	// Calculate scan rate (ports per second)
	var scanRate float64
	if elapsed.Seconds() > 0 {
		scanRate = float64(pm.portsScanned) / elapsed.Seconds()
	}

	// Calculate estimated time remaining
	var estimatedTime time.Duration
	if scanRate > 0 && pm.totalPorts > 0 {
		remaining := pm.totalPorts - pm.portsScanned
		if remaining > 0 {
			estimatedTime = time.Duration(float64(remaining)/scanRate) * time.Second
		}
	}

	return ProgressInfo{
		HostsScanned:  pm.hostsScanned,
		HostsTotal:    pm.totalHosts,
		PortsScanned:  pm.portsScanned,
		PortsTotal:    pm.totalPorts,
		ElapsedTime:   elapsed,
		EstimatedTime: estimatedTime,
		ScanRate:      scanRate,
		CurrentTarget: pm.currentTarget,
		CurrentPort:   pm.currentPort,
	}
}

// ConsoleProgressDisplay provides real-time progress display in console interface
type ConsoleProgressDisplay struct {
	monitor  ProgressMonitor
	lastLine string
	mutex    sync.Mutex
}

// NewConsoleProgressDisplay creates a new console progress display
func NewConsoleProgressDisplay(monitor ProgressMonitor) *ConsoleProgressDisplay {
	return &ConsoleProgressDisplay{
		monitor: monitor,
	}
}

// DisplayProgress displays progress information in the console (Requirements 8.1, 8.2)
func (cpd *ConsoleProgressDisplay) DisplayProgress(progress ProgressInfo) {
	cpd.mutex.Lock()
	defer cpd.mutex.Unlock()

	// Calculate completion percentages
	var hostPercent, portPercent float64
	if progress.HostsTotal > 0 {
		hostPercent = float64(progress.HostsScanned) / float64(progress.HostsTotal) * 100
	}
	if progress.PortsTotal > 0 {
		portPercent = float64(progress.PortsScanned) / float64(progress.PortsTotal) * 100
	}

	// Format elapsed and estimated time
	elapsedStr := formatDuration(progress.ElapsedTime)
	etaStr := "unknown"
	if progress.EstimatedTime > 0 {
		etaStr = formatDuration(progress.EstimatedTime)
	}

	// Create progress line
	line := fmt.Sprintf(
		"Progress: Hosts %d/%d (%.1f%%) | Ports %d/%d (%.1f%%) | Rate: %.1f p/s | Elapsed: %s | ETA: %s",
		progress.HostsScanned, progress.HostsTotal, hostPercent,
		progress.PortsScanned, progress.PortsTotal, portPercent,
		progress.ScanRate,
		elapsedStr, etaStr,
	)

	// Add current target info if available
	if progress.CurrentTarget != "" {
		line += fmt.Sprintf(" | Current: %s:%d", progress.CurrentTarget, progress.CurrentPort)
	}

	// Clear previous line and print new one
	if cpd.lastLine != "" {
		// Clear the previous line by overwriting with spaces
		clearLine := "\r" + fmt.Sprintf("%-*s", len(cpd.lastLine), " ") + "\r"
		fmt.Print(clearLine)
	}

	fmt.Printf("\r%s", line)
	cpd.lastLine = line
}

// Finish completes the progress display with a final newline
func (cpd *ConsoleProgressDisplay) Finish() {
	cpd.mutex.Lock()
	defer cpd.mutex.Unlock()

	if cpd.lastLine != "" {
		fmt.Println() // Add newline to finish the progress display
		cpd.lastLine = ""
	}
}

// formatDuration formats a duration in a human-readable way
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return "0s"
	}

	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if hours > 0 {
		return fmt.Sprintf("%dh%dm%ds", hours, minutes, seconds)
	} else if minutes > 0 {
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	} else {
		return fmt.Sprintf("%ds", seconds)
	}
}

// ProgressBarDisplay provides a visual progress bar for console output
type ProgressBarDisplay struct {
	width int
}

// NewProgressBarDisplay creates a new progress bar display
func NewProgressBarDisplay(width int) *ProgressBarDisplay {
	if width <= 0 {
		width = 50 // Default width
	}
	return &ProgressBarDisplay{
		width: width,
	}
}

// RenderProgressBar renders a progress bar for the given completion percentage
func (pbd *ProgressBarDisplay) RenderProgressBar(percent float64) string {
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}

	filled := int(percent / 100 * float64(pbd.width))
	empty := pbd.width - filled

	bar := "["
	for i := 0; i < filled; i++ {
		bar += "="
	}
	for i := 0; i < empty; i++ {
		bar += " "
	}
	bar += "]"

	return fmt.Sprintf("%s %.1f%%", bar, percent)
}

// CombinedProgressDisplay combines multiple progress displays
type CombinedProgressDisplay struct {
	displays []ProgressCallback
}

// NewCombinedProgressDisplay creates a combined progress display
func NewCombinedProgressDisplay(displays ...ProgressCallback) *CombinedProgressDisplay {
	return &CombinedProgressDisplay{
		displays: displays,
	}
}

// DisplayProgress calls all registered progress displays
func (cpd *CombinedProgressDisplay) DisplayProgress(progress ProgressInfo) {
	for _, display := range cpd.displays {
		if display != nil {
			display(progress)
		}
	}
}

// GetProgressCallback returns a progress callback function
func (cpd *CombinedProgressDisplay) GetProgressCallback() ProgressCallback {
	return cpd.DisplayProgress
}
