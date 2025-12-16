package networkmapper

import (
	"context"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

// ScanState represents the current state of a scan
type ScanState int

const (
	ScanStateIdle ScanState = iota
	ScanStateRunning
	ScanStatePaused
	ScanStateStopped
)

// String returns the string representation of ScanState
func (ss ScanState) String() string {
	switch ss {
	case ScanStateIdle:
		return "idle"
	case ScanStateRunning:
		return "running"
	case ScanStatePaused:
		return "paused"
	case ScanStateStopped:
		return "stopped"
	default:
		return "unknown"
	}
}

// ConcurrentScannerEngine implements the ScannerEngine interface with goroutine-based concurrency
type ConcurrentScannerEngine struct {
	portScanner     PortScanner
	serviceDetector ServiceDetector
	osFingerprinter OSFingerprinter
	targetResolver  TargetResolver
	progressMonitor ProgressMonitor
	logger          *log.Logger

	// Comprehensive error handling and resource management
	nmLogger        *NetworkMapperLogger
	errorHandler    *ErrorHandler
	resourceManager *ResourceManager

	// State management
	state      ScanState
	stateMutex sync.RWMutex

	// Concurrency control
	maxConnections int
	connectionSem  chan struct{}

	// Scan control
	ctx        context.Context
	cancel     context.CancelFunc
	pauseChan  chan struct{}
	resumeChan chan struct{}

	// Progress tracking
	progress      ProgressInfo
	progressMutex sync.RWMutex
	startTime     time.Time

	// Statistics (atomic counters for thread safety)
	hostsScanned  int64
	portsScanned  int64
	openPorts     int64
	closedPorts   int64
	filteredPorts int64

	// Results
	results      *ScanResult
	resultsMutex sync.Mutex
}

// NewConcurrentScannerEngine creates a new concurrent scanner engine
func NewConcurrentScannerEngine(
	portScanner PortScanner,
	serviceDetector ServiceDetector,
	osFingerprinter OSFingerprinter,
	targetResolver TargetResolver,
	progressMonitor ProgressMonitor,
	logger *log.Logger,
) *ConcurrentScannerEngine {
	if logger == nil {
		logger = log.Default()
	}

	return &ConcurrentScannerEngine{
		portScanner:     portScanner,
		serviceDetector: serviceDetector,
		osFingerprinter: osFingerprinter,
		targetResolver:  targetResolver,
		progressMonitor: progressMonitor,
		logger:          logger,
		state:           ScanStateIdle,
		maxConnections:  100, // Default connection limit
		pauseChan:       make(chan struct{}),
		resumeChan:      make(chan struct{}),
	}
}

// NewConcurrentScannerEngineWithErrorHandling creates a new concurrent scanner engine with comprehensive error handling
func NewConcurrentScannerEngineWithErrorHandling(
	portScanner PortScanner,
	serviceDetector ServiceDetector,
	osFingerprinter OSFingerprinter,
	targetResolver TargetResolver,
	progressMonitor ProgressMonitor,
	nmLogger *NetworkMapperLogger,
	errorHandler *ErrorHandler,
	resourceManager *ResourceManager,
) *ConcurrentScannerEngine {
	if nmLogger == nil {
		nmLogger = NewNetworkMapperLogger("scanner-engine", LogLevelInfo)
	}
	if errorHandler == nil {
		errorHandler = NewErrorHandler(nmLogger, resourceManager)
	}
	if resourceManager == nil {
		resourceManager = NewResourceManager(DefaultResourceLimits(), nmLogger)
	}

	return &ConcurrentScannerEngine{
		portScanner:     portScanner,
		serviceDetector: serviceDetector,
		osFingerprinter: osFingerprinter,
		targetResolver:  targetResolver,
		progressMonitor: progressMonitor,
		logger:          nmLogger.ToStandardLogger(),
		nmLogger:        nmLogger,
		errorHandler:    errorHandler,
		resourceManager: resourceManager,
		state:           ScanStateIdle,
		maxConnections:  100, // Default connection limit
		pauseChan:       make(chan struct{}),
		resumeChan:      make(chan struct{}),
	}
}

// Scan performs a network scan with the given configuration (Requirements 2.2, 2.3, 8.3, 8.4)
func (e *ConcurrentScannerEngine) Scan(ctx context.Context, config ScanConfig) (*ScanResult, error) {
	// Comprehensive input validation (Requirements 1.5, 2.5)
	if err := e.validateScanConfig(config); err != nil {
		if e.errorHandler != nil {
			return nil, e.errorHandler.HandleValidationError(err, "scan_configuration")
		}
		return nil, fmt.Errorf("scan configuration validation failed: %w", err)
	}

	// Resource estimation and validation
	if e.resourceManager != nil {
		estimate, err := e.resourceManager.EstimateResourceRequirements(config)
		if err != nil {
			if e.errorHandler != nil {
				return nil, e.errorHandler.HandleResourceError(err, "resource_estimation")
			}
			return nil, fmt.Errorf("resource estimation failed: %w", err)
		}

		if e.nmLogger != nil {
			e.nmLogger.Info("Resource requirements estimated",
				"total_operations", estimate.TotalOperations,
				"estimated_duration", estimate.EstimatedDuration,
				"peak_goroutines", estimate.PeakGoroutines,
				"peak_connections", estimate.PeakConnections,
				"estimated_memory_mb", estimate.EstimatedMemoryMB)
		}
	}

	e.stateMutex.Lock()
	if e.state != ScanStateIdle {
		e.stateMutex.Unlock()
		err := fmt.Errorf("scanner is already running or in invalid state: %s", e.state)
		if e.errorHandler != nil {
			return nil, e.errorHandler.HandleValidationError(ValidationError{
				Field:   "scanner_state",
				Value:   e.state,
				Message: err.Error(),
			}, "scan_start")
		}
		return nil, err
	}
	e.state = ScanStateRunning
	e.stateMutex.Unlock()

	// Log scan start
	if e.nmLogger != nil {
		e.nmLogger.LogScanStart(config)
	}

	// Initialize scan context and cancellation
	e.ctx, e.cancel = context.WithCancel(ctx)
	defer e.cancel()

	// Set connection limit based on config (Requirements 2.3)
	if config.MaxThreads > 0 {
		e.maxConnections = config.MaxThreads
	}
	e.connectionSem = make(chan struct{}, e.maxConnections)

	// Initialize progress tracking
	e.startTime = time.Now()
	e.resetCounters()

	// Resolve targets with error handling
	targets, err := e.resolveTargetsWithErrorHandling(config.Targets)
	if err != nil {
		e.setState(ScanStateIdle)
		return nil, err
	}

	// Determine ports to scan
	ports := e.determinePorts(config)

	// Calculate total hosts and ports
	totalHosts := 0
	for _, target := range targets {
		totalHosts += len(target.IPs)
	}
	totalPorts := totalHosts * len(ports)

	// Initialize results
	e.results = &ScanResult{
		Timestamp:  time.Now(),
		ScanConfig: config,
		Hosts:      make([]HostResult, 0, totalHosts),
		Statistics: ScanStatistics{
			HostsTotal: totalHosts,
			PortsTotal: totalPorts,
			StartTime:  e.startTime,
		},
	}

	// Start progress monitoring (Requirements 2.4, 8.1, 8.2)
	if e.progressMonitor != nil {
		e.progressMonitor.Start(totalHosts, totalPorts)
	}

	// Update progress info
	e.updateProgress(0, 0, totalHosts, totalPorts, "", 0)

	// Scan all targets concurrently
	var wg sync.WaitGroup
	hostResults := make(chan HostResult, len(targets))

	for _, target := range targets {
		for _, ip := range target.IPs {
			wg.Add(1)
			go func(targetIP string, originalTarget string) {
				defer wg.Done()

				// Check for cancellation or pause
				if err := e.checkScanState(); err != nil {
					e.logger.Printf("Scan interrupted for target %s: %v", targetIP, err)
					return
				}

				result := e.scanHost(targetIP, originalTarget, ports, config)
				hostResults <- result

				// Update host counter
				atomic.AddInt64(&e.hostsScanned, 1)

				// Call progress callback if provided
				if config.OnProgress != nil {
					config.OnProgress(e.GetProgress())
				}
			}(ip.String(), target.Original)
		}
	}

	// Wait for all scans to complete
	go func() {
		wg.Wait()
		close(hostResults)
	}()

	// Collect results
	for hostResult := range hostResults {
		e.resultsMutex.Lock()
		e.results.Hosts = append(e.results.Hosts, hostResult)
		e.resultsMutex.Unlock()
	}

	// Finalize results
	e.finalizeResults()

	// Stop progress monitoring (Requirements 2.4, 8.1, 8.2)
	if e.progressMonitor != nil {
		e.progressMonitor.Stop()
	}

	// Set state back to idle
	e.setState(ScanStateIdle)

	// Apply comprehensive validation to the final result
	return e.applyScanResultValidation(e.results)
}

// Pause suspends the current scan (Requirements 8.3)
func (e *ConcurrentScannerEngine) Pause() error {
	e.stateMutex.Lock()
	defer e.stateMutex.Unlock()

	if e.state != ScanStateRunning {
		return fmt.Errorf("cannot pause scan in state: %s", e.state)
	}

	e.state = ScanStatePaused
	e.logger.Println("Scan paused")
	return nil
}

// Resume continues a paused scan (Requirements 8.3)
func (e *ConcurrentScannerEngine) Resume() error {
	e.stateMutex.Lock()
	defer e.stateMutex.Unlock()

	if e.state != ScanStatePaused {
		return fmt.Errorf("cannot resume scan in state: %s", e.state)
	}

	e.state = ScanStateRunning
	e.logger.Println("Scan resumed")

	// Close and recreate the resume channel to signal all waiting goroutines
	close(e.resumeChan)
	e.resumeChan = make(chan struct{})

	return nil
}

// Stop terminates the current scan (Requirements 8.4)
func (e *ConcurrentScannerEngine) Stop() error {
	e.stateMutex.Lock()
	defer e.stateMutex.Unlock()

	if e.state != ScanStateRunning && e.state != ScanStatePaused {
		return fmt.Errorf("cannot stop scan in state: %s", e.state)
	}

	e.state = ScanStateStopped

	// Cancel the scan context
	if e.cancel != nil {
		e.cancel()
	}

	e.logger.Println("Scan stopped")
	return nil
}

// GetProgress returns current scan progress information (Requirements 8.1, 8.2)
func (e *ConcurrentScannerEngine) GetProgress() ProgressInfo {
	// Use progress monitor if available (Requirements 2.4, 8.1, 8.2)
	if e.progressMonitor != nil {
		return e.progressMonitor.GetProgress()
	}

	// Fallback to internal calculation
	e.progressMutex.RLock()
	defer e.progressMutex.RUnlock()

	// Calculate elapsed time and scan rate
	elapsed := time.Since(e.startTime)
	portsScanned := atomic.LoadInt64(&e.portsScanned)
	scanRate := float64(portsScanned) / elapsed.Seconds()

	// Estimate remaining time
	var estimatedTime time.Duration
	if scanRate > 0 && e.progress.PortsTotal > 0 {
		remaining := e.progress.PortsTotal - int(portsScanned)
		estimatedTime = time.Duration(float64(remaining)/scanRate) * time.Second
	}

	return ProgressInfo{
		HostsScanned:  int(atomic.LoadInt64(&e.hostsScanned)),
		HostsTotal:    e.progress.HostsTotal,
		PortsScanned:  int(portsScanned),
		PortsTotal:    e.progress.PortsTotal,
		ElapsedTime:   elapsed,
		EstimatedTime: estimatedTime,
		ScanRate:      scanRate,
		CurrentTarget: e.progress.CurrentTarget,
		CurrentPort:   e.progress.CurrentPort,
	}
}

// scanHost scans all ports on a single host
func (e *ConcurrentScannerEngine) scanHost(target, originalTarget string, ports []int, config ScanConfig) HostResult {
	startTime := time.Now()

	hostResult := HostResult{
		Target: originalTarget,
		Status: HostDown, // Will be updated if any ports respond
		Ports:  make([]PortResult, 0, len(ports)),
	}

	// Scan ports with concurrency control
	var wg sync.WaitGroup
	portResults := make(chan PortResult, len(ports))

	for _, port := range ports {
		// Check for cancellation or pause before each port
		if err := e.checkScanState(); err != nil {
			break
		}

		// Acquire connection semaphore (Requirements 2.3)
		e.connectionSem <- struct{}{}

		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			defer func() { <-e.connectionSem }() // Release semaphore

			// Update current scanning info
			e.updateProgress(0, 0, 0, 0, target, p)

			// Update progress monitor (Requirements 2.4, 8.1, 8.2)
			if e.progressMonitor != nil {
				hostsScanned := int(atomic.LoadInt64(&e.hostsScanned))
				portsScanned := int(atomic.LoadInt64(&e.portsScanned))
				e.progressMonitor.UpdateProgress(hostsScanned, portsScanned, target, p)
			}

			// Scan the port
			result := e.portScanner.ScanPort(e.ctx, target, p, config.ScanType)

			// Perform service detection if enabled and port is open
			if config.ServiceDetect && result.State == PortOpen && e.serviceDetector != nil {
				result.Service = e.serviceDetector.DetectService(e.ctx, target, p)
			}

			portResults <- result

			// Update port counter
			atomic.AddInt64(&e.portsScanned, 1)

			// Update port state counters
			switch result.State {
			case PortOpen:
				atomic.AddInt64(&e.openPorts, 1)
			case PortClosed:
				atomic.AddInt64(&e.closedPorts, 1)
			case PortFiltered:
				atomic.AddInt64(&e.filteredPorts, 1)
			}
		}(port)
	}

	// Wait for all port scans to complete
	go func() {
		wg.Wait()
		close(portResults)
	}()

	// Collect port results
	openPorts := make([]int, 0)
	for portResult := range portResults {
		hostResult.Ports = append(hostResult.Ports, portResult)
		if portResult.State == PortOpen {
			openPorts = append(openPorts, portResult.Port)
			hostResult.Status = HostUp // Host is up if any port is open
		}
	}

	// Perform OS detection if enabled and we have open ports
	if config.OSDetect && len(openPorts) > 0 && e.osFingerprinter != nil {
		if err := e.checkScanState(); err == nil {
			hostResult.OS = e.osFingerprinter.DetectOS(e.ctx, target, openPorts)
		}
	}

	hostResult.ResponseTime = time.Since(startTime)
	return hostResult
}

// checkScanState checks if the scan should continue or wait/stop
func (e *ConcurrentScannerEngine) checkScanState() error {
	for {
		e.stateMutex.RLock()
		state := e.state
		e.stateMutex.RUnlock()

		switch state {
		case ScanStateRunning:
			return nil
		case ScanStatePaused:
			// Wait for resume signal or context cancellation
			select {
			case <-e.resumeChan:
				// Check state again after resume signal
				continue
			case <-e.ctx.Done():
				return e.ctx.Err()
			}
		case ScanStateStopped:
			return fmt.Errorf("scan stopped")
		default:
			return fmt.Errorf("invalid scan state: %s", state)
		}
	}
}

// setState safely updates the scan state
func (e *ConcurrentScannerEngine) setState(state ScanState) {
	e.stateMutex.Lock()
	e.state = state
	e.stateMutex.Unlock()
}

// updateProgress updates the progress information
func (e *ConcurrentScannerEngine) updateProgress(hostsScanned, portsScanned, hostsTotal, portsTotal int, currentTarget string, currentPort int) {
	e.progressMutex.Lock()
	defer e.progressMutex.Unlock()

	// Update totals if provided
	if hostsTotal > 0 {
		e.progress.HostsTotal = hostsTotal
	}
	if portsTotal > 0 {
		e.progress.PortsTotal = portsTotal
	}

	// Update current scanning info
	if currentTarget != "" {
		e.progress.CurrentTarget = currentTarget
	}
	if currentPort > 0 {
		e.progress.CurrentPort = currentPort
	}

	// Update scanned counts if provided (use atomic values if not)
	if hostsScanned > 0 {
		e.progress.HostsScanned = hostsScanned
	} else {
		e.progress.HostsScanned = int(atomic.LoadInt64(&e.hostsScanned))
	}

	if portsScanned > 0 {
		e.progress.PortsScanned = portsScanned
	} else {
		e.progress.PortsScanned = int(atomic.LoadInt64(&e.portsScanned))
	}
}

// resetCounters resets all atomic counters
func (e *ConcurrentScannerEngine) resetCounters() {
	atomic.StoreInt64(&e.hostsScanned, 0)
	atomic.StoreInt64(&e.portsScanned, 0)
	atomic.StoreInt64(&e.openPorts, 0)
	atomic.StoreInt64(&e.closedPorts, 0)
	atomic.StoreInt64(&e.filteredPorts, 0)
}

// determinePorts determines which ports to scan based on configuration
func (e *ConcurrentScannerEngine) determinePorts(config ScanConfig) []int {
	var ports []int

	// Add specific ports
	ports = append(ports, config.Ports...)

	// Add ports from ranges
	for _, portRange := range config.PortRanges {
		for p := portRange.Start; p <= portRange.End; p++ {
			if isValidPort(p) {
				ports = append(ports, p)
			}
		}
	}

	// If no ports specified, use default top 1000 ports (Requirements 1.4)
	if len(ports) == 0 {
		ports = getTop1000Ports()
	}

	// Remove duplicates
	portMap := make(map[int]bool)
	uniquePorts := make([]int, 0, len(ports))
	for _, port := range ports {
		if !portMap[port] && isValidPort(port) {
			portMap[port] = true
			uniquePorts = append(uniquePorts, port)
		}
	}

	return uniquePorts
}

// finalizeResults calculates final statistics
func (e *ConcurrentScannerEngine) finalizeResults() {
	e.resultsMutex.Lock()
	defer e.resultsMutex.Unlock()

	endTime := time.Now()
	elapsed := endTime.Sub(e.startTime)

	e.results.Statistics = ScanStatistics{
		HostsScanned:  int(atomic.LoadInt64(&e.hostsScanned)),
		HostsTotal:    e.results.Statistics.HostsTotal,
		PortsScanned:  int(atomic.LoadInt64(&e.portsScanned)),
		PortsTotal:    e.results.Statistics.PortsTotal,
		OpenPorts:     int(atomic.LoadInt64(&e.openPorts)),
		ClosedPorts:   int(atomic.LoadInt64(&e.closedPorts)),
		FilteredPorts: int(atomic.LoadInt64(&e.filteredPorts)),
		StartTime:     e.startTime,
		EndTime:       endTime,
		ElapsedTime:   elapsed,
		ScanRate:      float64(atomic.LoadInt64(&e.portsScanned)) / elapsed.Seconds(),
	}
}

// getTop1000Ports returns the top 1000 most common ports (Requirements 1.4)
func getTop1000Ports() []int {
	// This is a subset of the most common ports for demonstration
	// In a real implementation, this would be the full top 1000 ports
	return []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
		143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080,
		// Add more ports as needed...
	}
}

// validateScanConfig performs comprehensive validation of scan configuration
// Implements Requirements 1.5, 2.5
func (e *ConcurrentScannerEngine) validateScanConfig(config ScanConfig) error {
	// Use comprehensive validation if available
	if e.resourceManager != nil {
		return ValidateComprehensive(config, e.resourceManager.GetResourceLimits())
	}

	// Fallback to basic validation
	return ValidateScanConfig(config)
}

// resolveTargetsWithErrorHandling resolves targets with comprehensive error handling
func (e *ConcurrentScannerEngine) resolveTargetsWithErrorHandling(targets []string) ([]NetworkTarget, error) {
	if e.errorHandler != nil {
		var resolvedTargets []NetworkTarget
		err := e.errorHandler.HandleNetworkOperation(e.ctx, "target_resolution", "", 0, func() error {
			resolved, resolveErr := e.targetResolver.ResolveTargets(targets)
			if resolveErr != nil {
				return resolveErr
			}
			resolvedTargets = resolved
			return nil
		})

		if err != nil {
			return nil, fmt.Errorf("failed to resolve targets: %w", err)
		}
		return resolvedTargets, nil
	}

	// Fallback to basic resolution
	resolved, err := e.targetResolver.ResolveTargets(targets)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve targets: %w", err)
	}
	return resolved, nil
}

// handleScanError handles errors that occur during scanning with graceful degradation
func (e *ConcurrentScannerEngine) handleScanError(err error, operation, target string, port int) {
	if e.errorHandler != nil {
		// Use comprehensive error handling
		nmErr, _ := e.errorHandler.HandleError(err, operation, target, port)

		// Check if we should apply graceful degradation
		if nmErr != nil && nmErr.Type == ErrorTypeResource {
			// Apply graceful degradation for resource errors
			e.errorHandler.GracefulDegradation(operation, "scanning", "high", "normal")

			// Reduce concurrency temporarily
			if e.maxConnections > 10 {
				e.maxConnections = e.maxConnections / 2
				e.connectionSem = make(chan struct{}, e.maxConnections)

				if e.nmLogger != nil {
					e.nmLogger.Warn("Reducing scan concurrency due to resource constraints",
						"new_max_connections", e.maxConnections)
				}
			}
		}
	} else {
		// Fallback to basic error logging
		e.logger.Printf("Scan error for %s:%d in operation %s: %v", target, port, operation, err)
	}
}

// recoverFromPanic recovers from panics in scan operations
func (e *ConcurrentScannerEngine) recoverFromPanic(operation, target string, port int) {
	if r := recover(); r != nil {
		if e.errorHandler != nil {
			e.errorHandler.RecoverFromPanic(operation, target, port)
		} else {
			e.logger.Printf("Panic recovered in %s for %s:%d: %v", operation, target, port, r)
		}
	}
}

// validateScanResult validates the final scan result for completeness
// Implements Requirements 1.3, 3.3, 4.2
func (e *ConcurrentScannerEngine) validateScanResult(result *ScanResult) error {
	if result == nil {
		return NewValidationError("scan_result", "scan result cannot be nil")
	}

	// Use comprehensive validation if available
	return ValidateScanResult(result)
}

// applyScanResultValidation applies validation to the scan result before returning
func (e *ConcurrentScannerEngine) applyScanResultValidation(result *ScanResult) (*ScanResult, error) {
	// Validate the result
	if err := e.validateScanResult(result); err != nil {
		if e.errorHandler != nil {
			return nil, e.errorHandler.HandleValidationError(err, "scan_result_validation")
		}
		return nil, fmt.Errorf("scan result validation failed: %w", err)
	}

	// Log scan completion
	if e.nmLogger != nil {
		e.nmLogger.LogScanComplete(result)
	}

	return result, nil
}
