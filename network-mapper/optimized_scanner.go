package networkmapper

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// OptimizedPortScanner implements an optimized version of PortScanner with performance monitoring
type OptimizedPortScanner struct {
	baseScanner     *DefaultPortScanner
	resourceManager *ResourceManager
	logger          *NetworkMapperLogger

	// Performance metrics
	scanCount     int64
	totalScanTime int64 // nanoseconds
	errorCount    int64
	timeoutCount  int64

	// Optimization settings
	batchSize       int
	adaptiveTimeout bool
	connectionPool  *ConnectionPool

	// Memory monitoring
	memoryThreshold float64 // MB
	lastGCTime      time.Time
	gcInterval      time.Duration
}

// NewOptimizedPortScanner creates a new optimized port scanner
func NewOptimizedPortScanner(timeout time.Duration, maxRetries int, resourceManager *ResourceManager, logger *NetworkMapperLogger) *OptimizedPortScanner {
	if logger == nil {
		logger = NewNetworkMapperLogger("optimized-scanner", LogLevelInfo)
	}

	baseScanner := NewDefaultPortScanner(timeout, maxRetries, logger.ToStandardLogger())

	return &OptimizedPortScanner{
		baseScanner:     baseScanner,
		resourceManager: resourceManager,
		logger:          logger,
		batchSize:       50, // Process ports in batches
		adaptiveTimeout: true,
		memoryThreshold: 100.0, // 100MB threshold for GC
		gcInterval:      30 * time.Second,
		connectionPool:  NewConnectionPool(100, timeout),
	}
}

// ScanPort scans a single port with performance optimization and resource management
func (ops *OptimizedPortScanner) ScanPort(ctx context.Context, target string, port int, scanType ScanType) PortResult {
	startTime := time.Now()

	// Check memory usage before scanning
	if err := ops.checkMemoryUsage(); err != nil {
		ops.logger.Warn("Memory usage high, forcing garbage collection", "error", err.Error())
		ops.forceGarbageCollectionIfNeeded()
	}

	// Use resource manager for connection management
	var result PortResult
	err := ops.resourceManager.WithConnectionManagement(ctx, "port_scan", target, port, func() error {
		result = ops.baseScanner.ScanPort(ctx, target, port, scanType)
		return nil
	})

	if err != nil {
		ops.logger.Error("Resource management error during port scan", "target", target, "port", port, "error", err.Error())
		atomic.AddInt64(&ops.errorCount, 1)
		return PortResult{
			Port:     port,
			Protocol: getProtocolForScanType(scanType),
			State:    PortFiltered,
		}
	}

	// Update performance metrics
	scanDuration := time.Since(startTime)
	atomic.AddInt64(&ops.scanCount, 1)
	atomic.AddInt64(&ops.totalScanTime, scanDuration.Nanoseconds())

	// Track timeouts
	if scanDuration >= ops.baseScanner.timeout {
		atomic.AddInt64(&ops.timeoutCount, 1)
	}

	// Adaptive timeout adjustment
	if ops.adaptiveTimeout {
		ops.adjustTimeoutIfNeeded()
	}

	return result
}

// ScanPorts scans multiple ports with optimized batching and resource management
func (ops *OptimizedPortScanner) ScanPorts(ctx context.Context, target string, ports []int, scanType ScanType) []PortResult {
	results := make([]PortResult, len(ports))

	// Process ports in batches to optimize memory usage and connection management
	for i := 0; i < len(ports); i += ops.batchSize {
		end := i + ops.batchSize
		if end > len(ports) {
			end = len(ports)
		}

		batch := ports[i:end]
		batchResults := ops.scanPortBatch(ctx, target, batch, scanType)

		// Copy batch results to main results array
		copy(results[i:end], batchResults)

		// Check if we should trigger garbage collection between batches
		if ops.shouldTriggerGC() {
			ops.forceGarbageCollectionIfNeeded()
		}

		// Small delay between batches to prevent overwhelming the target
		select {
		case <-ctx.Done():
			return results[:end] // Return partial results if cancelled
		case <-time.After(10 * time.Millisecond):
		}
	}

	return results
}

// scanPortBatch scans a batch of ports concurrently with resource limits
func (ops *OptimizedPortScanner) scanPortBatch(ctx context.Context, target string, ports []int, scanType ScanType) []PortResult {
	results := make([]PortResult, len(ports))
	var wg sync.WaitGroup

	// Use a semaphore to limit concurrent scans within the batch
	semaphore := make(chan struct{}, 20) // Limit to 20 concurrent scans per batch

	for i, port := range ports {
		wg.Add(1)
		go func(index, p int) {
			defer wg.Done()

			// Acquire semaphore
			select {
			case semaphore <- struct{}{}:
				defer func() { <-semaphore }()
			case <-ctx.Done():
				results[index] = PortResult{
					Port:     p,
					Protocol: getProtocolForScanType(scanType),
					State:    PortFiltered,
				}
				return
			}

			results[index] = ops.ScanPort(ctx, target, p, scanType)
		}(i, port)
	}

	wg.Wait()
	return results
}

// checkMemoryUsage checks current memory usage and returns error if too high
func (ops *OptimizedPortScanner) checkMemoryUsage() error {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	currentMB := float64(m.Alloc) / 1024 / 1024

	if currentMB > ops.memoryThreshold {
		return fmt.Errorf("memory usage %.2f MB exceeds threshold %.2f MB", currentMB, ops.memoryThreshold)
	}

	return nil
}

// shouldTriggerGC determines if garbage collection should be triggered
func (ops *OptimizedPortScanner) shouldTriggerGC() bool {
	if time.Since(ops.lastGCTime) < ops.gcInterval {
		return false
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	currentMB := float64(m.Alloc) / 1024 / 1024
	return currentMB > ops.memoryThreshold*0.8 // Trigger at 80% of threshold
}

// forceGarbageCollectionIfNeeded forces garbage collection if memory usage is high
func (ops *OptimizedPortScanner) forceGarbageCollectionIfNeeded() {
	var beforeGC runtime.MemStats
	runtime.ReadMemStats(&beforeGC)
	beforeMB := float64(beforeGC.Alloc) / 1024 / 1024

	ops.logger.Info("Forcing garbage collection", "memory_before_mb", beforeMB)

	runtime.GC()
	ops.lastGCTime = time.Now()

	var afterGC runtime.MemStats
	runtime.ReadMemStats(&afterGC)
	afterMB := float64(afterGC.Alloc) / 1024 / 1024

	ops.logger.Info("Garbage collection completed",
		"memory_before_mb", beforeMB,
		"memory_after_mb", afterMB,
		"freed_mb", beforeMB-afterMB)
}

// adjustTimeoutIfNeeded adjusts timeout based on performance metrics
func (ops *OptimizedPortScanner) adjustTimeoutIfNeeded() {
	scanCount := atomic.LoadInt64(&ops.scanCount)
	if scanCount < 100 { // Need enough samples
		return
	}

	timeoutCount := atomic.LoadInt64(&ops.timeoutCount)
	timeoutRate := float64(timeoutCount) / float64(scanCount)

	// If timeout rate is too high, increase timeout
	if timeoutRate > 0.3 { // More than 30% timeouts
		newTimeout := time.Duration(float64(ops.baseScanner.timeout) * 1.2)
		if newTimeout <= 60*time.Second { // Cap at 60 seconds
			ops.baseScanner.timeout = newTimeout
			ops.logger.Info("Increased timeout due to high timeout rate",
				"new_timeout", newTimeout,
				"timeout_rate", timeoutRate)
		}
	}

	// If timeout rate is very low, decrease timeout for faster scanning
	if timeoutRate < 0.05 && scanCount > 500 { // Less than 5% timeouts with enough samples
		newTimeout := time.Duration(float64(ops.baseScanner.timeout) * 0.9)
		if newTimeout >= 1*time.Second { // Don't go below 1 second
			ops.baseScanner.timeout = newTimeout
			ops.logger.Info("Decreased timeout due to low timeout rate",
				"new_timeout", newTimeout,
				"timeout_rate", timeoutRate)
		}
	}
}

// GetPerformanceMetrics returns current performance metrics
func (ops *OptimizedPortScanner) GetPerformanceMetrics() PerformanceMetrics {
	scanCount := atomic.LoadInt64(&ops.scanCount)
	totalTime := atomic.LoadInt64(&ops.totalScanTime)
	errorCount := atomic.LoadInt64(&ops.errorCount)
	timeoutCount := atomic.LoadInt64(&ops.timeoutCount)

	var avgScanTime time.Duration
	if scanCount > 0 {
		avgScanTime = time.Duration(totalTime / scanCount)
	}

	var errorRate, timeoutRate float64
	if scanCount > 0 {
		errorRate = float64(errorCount) / float64(scanCount)
		timeoutRate = float64(timeoutCount) / float64(scanCount)
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return PerformanceMetrics{
		TotalScans:      scanCount,
		AverageScanTime: avgScanTime,
		ErrorRate:       errorRate,
		TimeoutRate:     timeoutRate,
		MemoryUsageMB:   float64(m.Alloc) / 1024 / 1024,
		GoroutineCount:  runtime.NumGoroutine(),
	}
}

// ResetMetrics resets all performance metrics
func (ops *OptimizedPortScanner) ResetMetrics() {
	atomic.StoreInt64(&ops.scanCount, 0)
	atomic.StoreInt64(&ops.totalScanTime, 0)
	atomic.StoreInt64(&ops.errorCount, 0)
	atomic.StoreInt64(&ops.timeoutCount, 0)
}

// SetBatchSize sets the batch size for port scanning
func (ops *OptimizedPortScanner) SetBatchSize(size int) {
	if size > 0 && size <= 1000 {
		ops.batchSize = size
		ops.logger.Info("Updated batch size", "new_size", size)
	}
}

// SetMemoryThreshold sets the memory threshold for garbage collection
func (ops *OptimizedPortScanner) SetMemoryThreshold(thresholdMB float64) {
	if thresholdMB > 0 {
		ops.memoryThreshold = thresholdMB
		ops.logger.Info("Updated memory threshold", "new_threshold_mb", thresholdMB)
	}
}

// PerformanceMetrics contains performance statistics
type PerformanceMetrics struct {
	TotalScans      int64
	AverageScanTime time.Duration
	ErrorRate       float64
	TimeoutRate     float64
	MemoryUsageMB   float64
	GoroutineCount  int
}

// ConnectionPool manages a pool of reusable connections for optimization
type ConnectionPool struct {
	connections chan interface{}
	maxSize     int
	timeout     time.Duration
	mutex       sync.Mutex
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool(maxSize int, timeout time.Duration) *ConnectionPool {
	return &ConnectionPool{
		connections: make(chan interface{}, maxSize),
		maxSize:     maxSize,
		timeout:     timeout,
	}
}

// Get retrieves a connection from the pool or creates a new one
func (cp *ConnectionPool) Get() interface{} {
	select {
	case conn := <-cp.connections:
		return conn
	default:
		// No available connections, return nil to create new one
		return nil
	}
}

// Put returns a connection to the pool
func (cp *ConnectionPool) Put(conn interface{}) {
	if conn == nil {
		return
	}

	select {
	case cp.connections <- conn:
		// Successfully returned to pool
	default:
		// Pool is full, discard the connection
	}
}

// Close closes all connections in the pool
func (cp *ConnectionPool) Close() {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()

	// Drain the pool
	for {
		select {
		case <-cp.connections:
			// Connection drained
		default:
			return
		}
	}
}
