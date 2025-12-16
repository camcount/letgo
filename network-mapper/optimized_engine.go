package networkmapper

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// OptimizedScannerEngine implements an optimized version of ScannerEngine with performance monitoring
type OptimizedScannerEngine struct {
	// Base components
	portScanner     *OptimizedPortScanner
	serviceDetector ServiceDetector
	osFingerprinter OSFingerprinter
	targetResolver  TargetResolver
	progressMonitor ProgressMonitor
	resourceManager *ResourceManager
	fdManager       *FileDescriptorManager
	logger          *NetworkMapperLogger

	// State management
	state      ScanState
	stateMutex sync.RWMutex

	// Scan control
	ctx        context.Context
	cancel     context.CancelFunc
	pauseChan  chan struct{}
	resumeChan chan struct{}

	// Progress tracking
	progress      ProgressInfo
	progressMutex sync.RWMutex
	startTime     time.Time

	// Performance optimization
	batchProcessor    *BatchProcessor
	adaptiveScheduler *AdaptiveScheduler
	memoryMonitor     *MemoryMonitor

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

// NewOptimizedScannerEngine creates a new optimized scanner engine
func NewOptimizedScannerEngine(
	portScanner *OptimizedPortScanner,
	serviceDetector ServiceDetector,
	osFingerprinter OSFingerprinter,
	targetResolver TargetResolver,
	progressMonitor ProgressMonitor,
	resourceManager *ResourceManager,
	fdManager *FileDescriptorManager,
	logger *NetworkMapperLogger,
) *OptimizedScannerEngine {
	if logger == nil {
		logger = NewNetworkMapperLogger("optimized-engine", LogLevelInfo)
	}

	engine := &OptimizedScannerEngine{
		portScanner:     portScanner,
		serviceDetector: serviceDetector,
		osFingerprinter: osFingerprinter,
		targetResolver:  targetResolver,
		progressMonitor: progressMonitor,
		resourceManager: resourceManager,
		fdManager:       fdManager,
		logger:          logger,
		state:           ScanStateIdle,
		pauseChan:       make(chan struct{}),
		resumeChan:      make(chan struct{}),
	}

	// Initialize performance optimization components
	engine.batchProcessor = NewBatchProcessor(50, logger) // 50 operations per batch
	engine.adaptiveScheduler = NewAdaptiveScheduler(logger)
	engine.memoryMonitor = NewMemoryMonitor(512.0, logger) // 512MB threshold

	return engine
}

// Scan performs an optimized network scan with performance monitoring
func (ose *OptimizedScannerEngine) Scan(ctx context.Context, config ScanConfig) (*ScanResult, error) {
	ose.stateMutex.Lock()
	if ose.state != ScanStateIdle {
		ose.stateMutex.Unlock()
		return nil, fmt.Errorf("scanner is already running or in invalid state: %s", ose.state)
	}
	ose.state = ScanStateRunning
	ose.stateMutex.Unlock()

	// Initialize scan context and cancellation
	ose.ctx, ose.cancel = context.WithCancel(ctx)
	defer ose.cancel()

	// Start performance monitoring
	ose.startTime = time.Now()
	ose.resetCounters()
	ose.memoryMonitor.Start()
	defer ose.memoryMonitor.Stop()

	// Estimate resource requirements
	estimate, err := ose.resourceManager.EstimateResourceRequirements(config)
	if err != nil {
		ose.setState(ScanStateIdle)
		return nil, fmt.Errorf("resource estimation failed: %w", err)
	}

	ose.logger.Info("Starting optimized scan",
		"total_operations", estimate.TotalOperations,
		"estimated_duration", estimate.EstimatedDuration,
		"peak_memory_mb", estimate.EstimatedMemoryMB)

	// Resolve targets
	targets, err := ose.targetResolver.ResolveTargets(config.Targets)
	if err != nil {
		ose.setState(ScanStateIdle)
		return nil, fmt.Errorf("failed to resolve targets: %w", err)
	}

	// Determine ports to scan
	ports := ose.determinePorts(config)

	// Calculate total hosts and ports
	totalHosts := 0
	for _, target := range targets {
		totalHosts += len(target.IPs)
	}
	totalPorts := totalHosts * len(ports)

	// Initialize results
	ose.results = &ScanResult{
		Timestamp:  time.Now(),
		ScanConfig: config,
		Hosts:      make([]HostResult, 0, totalHosts),
		Statistics: ScanStatistics{
			HostsTotal: totalHosts,
			PortsTotal: totalPorts,
			StartTime:  ose.startTime,
		},
	}

	// Start progress monitoring
	if ose.progressMonitor != nil {
		ose.progressMonitor.Start(totalHosts, totalPorts)
	}

	// Update progress info
	ose.updateProgress(0, 0, totalHosts, totalPorts, "", 0)

	// Perform optimized scanning
	err = ose.performOptimizedScan(targets, ports, config)
	if err != nil {
		ose.logger.Error("Optimized scan failed", "error", err.Error())
	}

	// Finalize results
	ose.finalizeResults()

	// Stop progress monitoring
	if ose.progressMonitor != nil {
		ose.progressMonitor.Stop()
	}

	// Log performance metrics
	ose.logPerformanceMetrics()

	// Set state back to idle
	ose.setState(ScanStateIdle)

	return ose.results, err
}

// performOptimizedScan performs the actual scanning with optimizations
func (ose *OptimizedScannerEngine) performOptimizedScan(targets []NetworkTarget, ports []int, config ScanConfig) error {
	// Create scan jobs
	jobs := ose.createScanJobs(targets, ports, config)

	// Process jobs in optimized batches
	return ose.batchProcessor.ProcessJobs(ose.ctx, jobs, func(job ScanJob) error {
		return ose.processScanJob(job)
	})
}

// createScanJobs creates individual scan jobs for batch processing
func (ose *OptimizedScannerEngine) createScanJobs(targets []NetworkTarget, ports []int, config ScanConfig) []ScanJob {
	var jobs []ScanJob

	for _, target := range targets {
		for _, ip := range target.IPs {
			job := ScanJob{
				Target:         ip.String(),
				OriginalTarget: target.Original,
				Ports:          ports,
				Config:         config,
			}
			jobs = append(jobs, job)
		}
	}

	// Optimize job order using adaptive scheduler
	return ose.adaptiveScheduler.OptimizeJobOrder(jobs)
}

// processScanJob processes a single scan job
func (ose *OptimizedScannerEngine) processScanJob(job ScanJob) error {
	// Check for cancellation or pause
	if err := ose.checkScanState(); err != nil {
		return err
	}

	// Check memory usage before processing
	if err := ose.memoryMonitor.CheckMemoryUsage(); err != nil {
		ose.logger.Warn("High memory usage detected", "error", err.Error())
		ose.memoryMonitor.ForceGarbageCollection()
	}

	// Scan the host
	hostResult := ose.scanHostOptimized(job.Target, job.OriginalTarget, job.Ports, job.Config)

	// Store result
	ose.resultsMutex.Lock()
	ose.results.Hosts = append(ose.results.Hosts, hostResult)
	ose.resultsMutex.Unlock()

	// Update counters
	atomic.AddInt64(&ose.hostsScanned, 1)

	// Update progress
	if ose.progressMonitor != nil {
		hostsScanned := int(atomic.LoadInt64(&ose.hostsScanned))
		portsScanned := int(atomic.LoadInt64(&ose.portsScanned))
		ose.progressMonitor.UpdateProgress(hostsScanned, portsScanned, job.Target, 0)
	}

	return nil
}

// scanHostOptimized scans all ports on a single host with optimizations
func (ose *OptimizedScannerEngine) scanHostOptimized(target, originalTarget string, ports []int, config ScanConfig) HostResult {
	startTime := time.Now()

	hostResult := HostResult{
		Target: originalTarget,
		Status: HostDown,
		Ports:  make([]PortResult, 0, len(ports)),
	}

	// Use optimized port scanner
	portResults := ose.portScanner.ScanPorts(ose.ctx, target, ports, config.ScanType)

	// Process port results
	openPorts := make([]int, 0)
	for _, portResult := range portResults {
		hostResult.Ports = append(hostResult.Ports, portResult)

		// Update port state counters
		switch portResult.State {
		case PortOpen:
			atomic.AddInt64(&ose.openPorts, 1)
			openPorts = append(openPorts, portResult.Port)
			hostResult.Status = HostUp
		case PortClosed:
			atomic.AddInt64(&ose.closedPorts, 1)
		case PortFiltered:
			atomic.AddInt64(&ose.filteredPorts, 1)
		}

		atomic.AddInt64(&ose.portsScanned, 1)
	}

	// Perform service detection if enabled and we have open ports
	if config.ServiceDetect && len(openPorts) > 0 && ose.serviceDetector != nil {
		ose.performServiceDetection(target, &hostResult, openPorts)
	}

	// Perform OS detection if enabled and we have open ports
	if config.OSDetect && len(openPorts) > 0 && ose.osFingerprinter != nil {
		if err := ose.checkScanState(); err == nil {
			hostResult.OS = ose.osFingerprinter.DetectOS(ose.ctx, target, openPorts)
		}
	}

	hostResult.ResponseTime = time.Since(startTime)
	return hostResult
}

// performServiceDetection performs service detection on open ports
func (ose *OptimizedScannerEngine) performServiceDetection(target string, hostResult *HostResult, openPorts []int) {
	// Use resource management for service detection
	for i, portResult := range hostResult.Ports {
		if portResult.State == PortOpen {
			err := ose.resourceManager.WithConnectionManagement(ose.ctx, "service_detection", target, portResult.Port, func() error {
				serviceInfo := ose.serviceDetector.DetectService(ose.ctx, target, portResult.Port)
				hostResult.Ports[i].Service = serviceInfo
				return nil
			})

			if err != nil {
				ose.logger.Warn("Service detection failed due to resource constraints",
					"target", target,
					"port", portResult.Port,
					"error", err.Error())
			}
		}
	}
}

// Pause suspends the current scan
func (ose *OptimizedScannerEngine) Pause() error {
	ose.stateMutex.Lock()
	defer ose.stateMutex.Unlock()

	if ose.state != ScanStateRunning {
		return fmt.Errorf("cannot pause scan in state: %s", ose.state)
	}

	ose.state = ScanStatePaused
	ose.logger.Info("Optimized scan paused")
	return nil
}

// Resume continues a paused scan
func (ose *OptimizedScannerEngine) Resume() error {
	ose.stateMutex.Lock()
	defer ose.stateMutex.Unlock()

	if ose.state != ScanStatePaused {
		return fmt.Errorf("cannot resume scan in state: %s", ose.state)
	}

	ose.state = ScanStateRunning
	ose.logger.Info("Optimized scan resumed")

	// Signal resume to all waiting goroutines
	close(ose.resumeChan)
	ose.resumeChan = make(chan struct{})

	return nil
}

// Stop terminates the current scan
func (ose *OptimizedScannerEngine) Stop() error {
	ose.stateMutex.Lock()
	defer ose.stateMutex.Unlock()

	if ose.state != ScanStateRunning && ose.state != ScanStatePaused {
		return fmt.Errorf("cannot stop scan in state: %s", ose.state)
	}

	ose.state = ScanStateStopped

	// Cancel the scan context
	if ose.cancel != nil {
		ose.cancel()
	}

	ose.logger.Info("Optimized scan stopped")
	return nil
}

// GetProgress returns current scan progress information
func (ose *OptimizedScannerEngine) GetProgress() ProgressInfo {
	if ose.progressMonitor != nil {
		return ose.progressMonitor.GetProgress()
	}

	// Fallback to internal calculation
	ose.progressMutex.RLock()
	defer ose.progressMutex.RUnlock()

	elapsed := time.Since(ose.startTime)
	portsScanned := atomic.LoadInt64(&ose.portsScanned)
	scanRate := float64(portsScanned) / elapsed.Seconds()

	var estimatedTime time.Duration
	if scanRate > 0 && ose.progress.PortsTotal > 0 {
		remaining := ose.progress.PortsTotal - int(portsScanned)
		if remaining > 0 {
			estimatedTime = time.Duration(float64(remaining)/scanRate) * time.Second
		}
	}

	return ProgressInfo{
		HostsScanned:  int(atomic.LoadInt64(&ose.hostsScanned)),
		HostsTotal:    ose.progress.HostsTotal,
		PortsScanned:  int(portsScanned),
		PortsTotal:    ose.progress.PortsTotal,
		ElapsedTime:   elapsed,
		EstimatedTime: estimatedTime,
		ScanRate:      scanRate,
		CurrentTarget: ose.progress.CurrentTarget,
		CurrentPort:   ose.progress.CurrentPort,
	}
}

// logPerformanceMetrics logs performance metrics at the end of the scan
func (ose *OptimizedScannerEngine) logPerformanceMetrics() {
	scannerMetrics := ose.portScanner.GetPerformanceMetrics()
	fdStats := ose.fdManager.GetFileDescriptorStats()

	ose.logger.Info("Scan performance metrics",
		"total_scans", scannerMetrics.TotalScans,
		"avg_scan_time", scannerMetrics.AverageScanTime,
		"error_rate", scannerMetrics.ErrorRate,
		"timeout_rate", scannerMetrics.TimeoutRate,
		"memory_usage_mb", scannerMetrics.MemoryUsageMB,
		"goroutine_count", scannerMetrics.GoroutineCount,
		"peak_fd_usage", fdStats.PeakUsage,
		"fd_utilization_percent", fdStats.UtilizationPercent)
}

// Helper methods (similar to base engine but optimized)
func (ose *OptimizedScannerEngine) checkScanState() error {
	for {
		ose.stateMutex.RLock()
		state := ose.state
		ose.stateMutex.RUnlock()

		switch state {
		case ScanStateRunning:
			return nil
		case ScanStatePaused:
			select {
			case <-ose.resumeChan:
				continue
			case <-ose.ctx.Done():
				return ose.ctx.Err()
			}
		case ScanStateStopped:
			return fmt.Errorf("scan stopped")
		default:
			return fmt.Errorf("invalid scan state: %s", state)
		}
	}
}

func (ose *OptimizedScannerEngine) setState(state ScanState) {
	ose.stateMutex.Lock()
	ose.state = state
	ose.stateMutex.Unlock()
}

func (ose *OptimizedScannerEngine) updateProgress(hostsScanned, portsScanned, hostsTotal, portsTotal int, currentTarget string, currentPort int) {
	ose.progressMutex.Lock()
	defer ose.progressMutex.Unlock()

	if hostsTotal > 0 {
		ose.progress.HostsTotal = hostsTotal
	}
	if portsTotal > 0 {
		ose.progress.PortsTotal = portsTotal
	}
	if currentTarget != "" {
		ose.progress.CurrentTarget = currentTarget
	}
	if currentPort > 0 {
		ose.progress.CurrentPort = currentPort
	}

	if hostsScanned > 0 {
		ose.progress.HostsScanned = hostsScanned
	} else {
		ose.progress.HostsScanned = int(atomic.LoadInt64(&ose.hostsScanned))
	}

	if portsScanned > 0 {
		ose.progress.PortsScanned = portsScanned
	} else {
		ose.progress.PortsScanned = int(atomic.LoadInt64(&ose.portsScanned))
	}
}

func (ose *OptimizedScannerEngine) resetCounters() {
	atomic.StoreInt64(&ose.hostsScanned, 0)
	atomic.StoreInt64(&ose.portsScanned, 0)
	atomic.StoreInt64(&ose.openPorts, 0)
	atomic.StoreInt64(&ose.closedPorts, 0)
	atomic.StoreInt64(&ose.filteredPorts, 0)
}

func (ose *OptimizedScannerEngine) determinePorts(config ScanConfig) []int {
	var ports []int

	ports = append(ports, config.Ports...)

	for _, portRange := range config.PortRanges {
		for p := portRange.Start; p <= portRange.End; p++ {
			if isValidPort(p) {
				ports = append(ports, p)
			}
		}
	}

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

func (ose *OptimizedScannerEngine) finalizeResults() {
	ose.resultsMutex.Lock()
	defer ose.resultsMutex.Unlock()

	endTime := time.Now()
	elapsed := endTime.Sub(ose.startTime)

	ose.results.Statistics = ScanStatistics{
		HostsScanned:  int(atomic.LoadInt64(&ose.hostsScanned)),
		HostsTotal:    ose.results.Statistics.HostsTotal,
		PortsScanned:  int(atomic.LoadInt64(&ose.portsScanned)),
		PortsTotal:    ose.results.Statistics.PortsTotal,
		OpenPorts:     int(atomic.LoadInt64(&ose.openPorts)),
		ClosedPorts:   int(atomic.LoadInt64(&ose.closedPorts)),
		FilteredPorts: int(atomic.LoadInt64(&ose.filteredPorts)),
		StartTime:     ose.startTime,
		EndTime:       endTime,
		ElapsedTime:   elapsed,
		ScanRate:      float64(atomic.LoadInt64(&ose.portsScanned)) / elapsed.Seconds(),
	}
}

// ScanJob represents a single scan job for batch processing
type ScanJob struct {
	Target         string
	OriginalTarget string
	Ports          []int
	Config         ScanConfig
}
