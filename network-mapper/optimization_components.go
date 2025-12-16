package networkmapper

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"time"
)

// BatchProcessor handles batch processing of scan jobs for optimization
type BatchProcessor struct {
	batchSize int
	logger    *NetworkMapperLogger
}

// NewBatchProcessor creates a new batch processor
func NewBatchProcessor(batchSize int, logger *NetworkMapperLogger) *BatchProcessor {
	if batchSize <= 0 {
		batchSize = 50 // Default batch size
	}

	return &BatchProcessor{
		batchSize: batchSize,
		logger:    logger,
	}
}

// ProcessJobs processes jobs in optimized batches
func (bp *BatchProcessor) ProcessJobs(ctx context.Context, jobs []ScanJob, processor func(ScanJob) error) error {
	totalJobs := len(jobs)
	bp.logger.Info("Starting batch processing", "total_jobs", totalJobs, "batch_size", bp.batchSize)

	for i := 0; i < totalJobs; i += bp.batchSize {
		end := i + bp.batchSize
		if end > totalJobs {
			end = totalJobs
		}

		batch := jobs[i:end]
		if err := bp.processBatch(ctx, batch, processor); err != nil {
			return fmt.Errorf("batch processing failed at batch %d-%d: %w", i, end-1, err)
		}

		// Check for cancellation between batches
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}

	bp.logger.Info("Batch processing completed", "total_jobs", totalJobs)
	return nil
}

// processBatch processes a single batch of jobs
func (bp *BatchProcessor) processBatch(ctx context.Context, batch []ScanJob, processor func(ScanJob) error) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(batch))

	for _, job := range batch {
		wg.Add(1)
		go func(j ScanJob) {
			defer wg.Done()
			if err := processor(j); err != nil {
				errChan <- err
			}
		}(job)
	}

	wg.Wait()
	close(errChan)

	// Check for errors
	for err := range errChan {
		if err != nil {
			return err
		}
	}

	return nil
}

// AdaptiveScheduler optimizes job scheduling based on performance characteristics
type AdaptiveScheduler struct {
	logger         *NetworkMapperLogger
	performanceMap map[string]time.Duration // Target -> average response time
	mutex          sync.RWMutex
}

// NewAdaptiveScheduler creates a new adaptive scheduler
func NewAdaptiveScheduler(logger *NetworkMapperLogger) *AdaptiveScheduler {
	return &AdaptiveScheduler{
		logger:         logger,
		performanceMap: make(map[string]time.Duration),
	}
}

// OptimizeJobOrder optimizes the order of jobs based on performance characteristics
func (as *AdaptiveScheduler) OptimizeJobOrder(jobs []ScanJob) []ScanJob {
	if len(jobs) <= 1 {
		return jobs
	}

	as.mutex.RLock()
	defer as.mutex.RUnlock()

	// Sort jobs by expected performance (faster targets first)
	sort.Slice(jobs, func(i, j int) bool {
		timeI := as.getExpectedTime(jobs[i].Target)
		timeJ := as.getExpectedTime(jobs[j].Target)
		return timeI < timeJ
	})

	as.logger.Debug("Optimized job order", "total_jobs", len(jobs))
	return jobs
}

// getExpectedTime returns the expected response time for a target
func (as *AdaptiveScheduler) getExpectedTime(target string) time.Duration {
	if avgTime, exists := as.performanceMap[target]; exists {
		return avgTime
	}
	// Default expected time for unknown targets
	return 5 * time.Second
}

// UpdatePerformance updates performance statistics for a target
func (as *AdaptiveScheduler) UpdatePerformance(target string, responseTime time.Duration) {
	as.mutex.Lock()
	defer as.mutex.Unlock()

	if existing, exists := as.performanceMap[target]; exists {
		// Calculate moving average (70% old, 30% new)
		as.performanceMap[target] = time.Duration(float64(existing)*0.7 + float64(responseTime)*0.3)
	} else {
		as.performanceMap[target] = responseTime
	}
}

// MemoryMonitor monitors and manages memory usage during scanning
type MemoryMonitor struct {
	thresholdMB     float64
	logger          *NetworkMapperLogger
	monitorInterval time.Duration
	ctx             context.Context
	cancel          context.CancelFunc
	isRunning       bool
	mutex           sync.Mutex
}

// NewMemoryMonitor creates a new memory monitor
func NewMemoryMonitor(thresholdMB float64, logger *NetworkMapperLogger) *MemoryMonitor {
	return &MemoryMonitor{
		thresholdMB:     thresholdMB,
		logger:          logger,
		monitorInterval: 5 * time.Second,
	}
}

// Start begins memory monitoring
func (mm *MemoryMonitor) Start() {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	if mm.isRunning {
		return
	}

	mm.ctx, mm.cancel = context.WithCancel(context.Background())
	mm.isRunning = true

	go mm.monitorMemory()
	mm.logger.Info("Memory monitoring started", "threshold_mb", mm.thresholdMB)
}

// Stop stops memory monitoring
func (mm *MemoryMonitor) Stop() {
	mm.mutex.Lock()
	defer mm.mutex.Unlock()

	if !mm.isRunning {
		return
	}

	mm.cancel()
	mm.isRunning = false
	mm.logger.Info("Memory monitoring stopped")
}

// CheckMemoryUsage checks current memory usage against threshold
func (mm *MemoryMonitor) CheckMemoryUsage() error {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	currentMB := float64(m.Alloc) / 1024 / 1024

	if currentMB > mm.thresholdMB {
		return fmt.Errorf("memory usage %.2f MB exceeds threshold %.2f MB", currentMB, mm.thresholdMB)
	}

	return nil
}

// ForceGarbageCollection forces garbage collection
func (mm *MemoryMonitor) ForceGarbageCollection() {
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	beforeMB := float64(before.Alloc) / 1024 / 1024

	mm.logger.Info("Forcing garbage collection", "memory_before_mb", beforeMB)

	runtime.GC()

	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	afterMB := float64(after.Alloc) / 1024 / 1024

	mm.logger.Info("Garbage collection completed",
		"memory_before_mb", beforeMB,
		"memory_after_mb", afterMB,
		"freed_mb", beforeMB-afterMB)
}

// monitorMemory continuously monitors memory usage
func (mm *MemoryMonitor) monitorMemory() {
	ticker := time.NewTicker(mm.monitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-mm.ctx.Done():
			return
		case <-ticker.C:
			mm.checkAndLogMemoryUsage()
		}
	}
}

// checkAndLogMemoryUsage checks memory usage and logs warnings if needed
func (mm *MemoryMonitor) checkAndLogMemoryUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	currentMB := float64(m.Alloc) / 1024 / 1024

	// Log warning if approaching threshold
	if currentMB > mm.thresholdMB*0.8 {
		mm.logger.Warn("High memory usage detected",
			"current_mb", currentMB,
			"threshold_mb", mm.thresholdMB,
			"percentage", (currentMB/mm.thresholdMB)*100)

		// Force GC if very close to threshold
		if currentMB > mm.thresholdMB*0.95 {
			mm.ForceGarbageCollection()
		}
	}
}

// GetMemoryStats returns current memory statistics
func (mm *MemoryMonitor) GetMemoryStats() MemoryStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return MemoryStats{
		AllocMB:       float64(m.Alloc) / 1024 / 1024,
		TotalAllocMB:  float64(m.TotalAlloc) / 1024 / 1024,
		SysMB:         float64(m.Sys) / 1024 / 1024,
		NumGC:         m.NumGC,
		GCCPUFraction: m.GCCPUFraction,
		ThresholdMB:   mm.thresholdMB,
	}
}

// MemoryStats contains memory usage statistics
type MemoryStats struct {
	AllocMB       float64
	TotalAllocMB  float64
	SysMB         float64
	NumGC         uint32
	GCCPUFraction float64
	ThresholdMB   float64
}

// ScanOptimizer provides various optimization strategies for scanning
type ScanOptimizer struct {
	logger *NetworkMapperLogger
}

// NewScanOptimizer creates a new scan optimizer
func NewScanOptimizer(logger *NetworkMapperLogger) *ScanOptimizer {
	return &ScanOptimizer{
		logger: logger,
	}
}

// OptimizePortOrder optimizes the order of ports to scan for better performance
func (so *ScanOptimizer) OptimizePortOrder(ports []int) []int {
	if len(ports) <= 1 {
		return ports
	}

	// Create a copy to avoid modifying the original
	optimized := make([]int, len(ports))
	copy(optimized, ports)

	// Sort by likelihood of being open (common ports first)
	sort.Slice(optimized, func(i, j int) bool {
		return so.getPortPriority(optimized[i]) > so.getPortPriority(optimized[j])
	})

	so.logger.Debug("Optimized port order", "total_ports", len(optimized))
	return optimized
}

// getPortPriority returns a priority score for a port (higher = more likely to be open)
func (so *ScanOptimizer) getPortPriority(port int) int {
	// Common ports get higher priority
	commonPorts := map[int]int{
		80:   100, // HTTP
		443:  95,  // HTTPS
		22:   90,  // SSH
		21:   85,  // FTP
		25:   80,  // SMTP
		53:   75,  // DNS
		110:  70,  // POP3
		143:  65,  // IMAP
		993:  60,  // IMAPS
		995:  55,  // POP3S
		3389: 50,  // RDP
		3306: 45,  // MySQL
		5432: 40,  // PostgreSQL
		1433: 35,  // MSSQL
		8080: 30,  // HTTP Alt
		8443: 25,  // HTTPS Alt
	}

	if priority, exists := commonPorts[port]; exists {
		return priority
	}

	// Well-known ports (1-1023) get medium priority
	if port <= 1023 {
		return 20
	}

	// Registered ports (1024-49151) get low priority
	if port <= 49151 {
		return 10
	}

	// Dynamic/private ports get lowest priority
	return 5
}

// OptimizeTargetOrder optimizes the order of targets for better scanning performance
func (so *ScanOptimizer) OptimizeTargetOrder(targets []string) []string {
	if len(targets) <= 1 {
		return targets
	}

	// Create a copy to avoid modifying the original
	optimized := make([]string, len(targets))
	copy(optimized, targets)

	// Sort targets to optimize scanning (local networks first, then by IP)
	sort.Slice(optimized, func(i, j int) bool {
		return so.getTargetPriority(optimized[i]) > so.getTargetPriority(optimized[j])
	})

	so.logger.Debug("Optimized target order", "total_targets", len(optimized))
	return optimized
}

// getTargetPriority returns a priority score for a target (higher = scan first)
func (so *ScanOptimizer) getTargetPriority(target string) int {
	// Local networks get higher priority (faster response times)
	if len(target) >= 9 && target == "127.0.0.1" {
		return 85 // Localhost
	}

	if len(target) >= 7 {
		switch {
		case target[:7] == "192.168":
			return 100 // Private network
		case len(target) >= 3 && target[:3] == "10.":
			return 95 // Private network
		case target[:7] == "172.16." || target[:7] == "172.17." ||
			target[:7] == "172.18." || target[:7] == "172.19." ||
			target[:7] == "172.20." || target[:7] == "172.21." ||
			target[:7] == "172.22." || target[:7] == "172.23." ||
			target[:7] == "172.24." || target[:7] == "172.25." ||
			target[:7] == "172.26." || target[:7] == "172.27." ||
			target[:7] == "172.28." || target[:7] == "172.29." ||
			target[:7] == "172.30." || target[:7] == "172.31.":
			return 90 // Private network
		}
	}

	// Public IPs get lower priority
	return 50
}

// CalculateOptimalBatchSize calculates the optimal batch size based on system resources
func (so *ScanOptimizer) CalculateOptimalBatchSize(totalJobs int, maxMemoryMB float64) int {
	// Get current system info
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	currentMemoryMB := float64(m.Alloc) / 1024 / 1024
	availableMemoryMB := maxMemoryMB - currentMemoryMB

	// Estimate memory per job (rough estimate)
	memoryPerJobMB := 0.1 // 100KB per job

	// Calculate max jobs that fit in available memory
	maxJobsForMemory := int(availableMemoryMB / memoryPerJobMB)

	// Consider CPU cores
	numCPU := runtime.NumCPU()
	optimalForCPU := numCPU * 10 // 10 jobs per CPU core

	// Take the minimum of memory and CPU constraints
	batchSize := maxJobsForMemory
	if optimalForCPU < batchSize {
		batchSize = optimalForCPU
	}

	// Ensure reasonable bounds
	if batchSize < 10 {
		batchSize = 10
	}
	if batchSize > 200 {
		batchSize = 200
	}

	// Don't exceed total jobs
	if batchSize > totalJobs {
		batchSize = totalJobs
	}

	so.logger.Info("Calculated optimal batch size",
		"batch_size", batchSize,
		"total_jobs", totalJobs,
		"available_memory_mb", availableMemoryMB,
		"num_cpu", numCPU)

	return batchSize
}
