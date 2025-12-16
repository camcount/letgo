package networkmapper

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ResourceLimits defines limits for various system resources
type ResourceLimits struct {
	MaxGoroutines  int           // Maximum number of concurrent goroutines
	MaxMemoryMB    float64       // Maximum memory usage in MB
	MaxOpenFiles   int           // Maximum number of open file descriptors
	MaxConnections int           // Maximum number of concurrent network connections
	ScanTimeout    time.Duration // Maximum time for a single scan operation
	OverallTimeout time.Duration // Maximum time for the entire scan
}

// DefaultResourceLimits returns sensible default resource limits
func DefaultResourceLimits() ResourceLimits {
	return ResourceLimits{
		MaxGoroutines:  1000,
		MaxMemoryMB:    512.0,
		MaxOpenFiles:   1000,
		MaxConnections: 100,
		ScanTimeout:    30 * time.Second,
		OverallTimeout: 24 * time.Hour,
	}
}

// ResourceUsage tracks current resource usage
type ResourceUsage struct {
	Goroutines  int     // Current number of goroutines
	MemoryMB    float64 // Current memory usage in MB
	OpenFiles   int     // Current number of open files
	Connections int64   // Current number of active connections (atomic)
	StartTime   time.Time
	LastUpdated time.Time
}

// ResourceManager manages system resources and enforces limits
type ResourceManager struct {
	limits ResourceLimits
	usage  ResourceUsage
	mutex  sync.RWMutex
	logger *NetworkMapperLogger

	// Semaphores for resource control
	connectionSem chan struct{}
	goroutineSem  chan struct{}

	// Monitoring
	monitorCtx      context.Context
	monitorCancel   context.CancelFunc
	monitorInterval time.Duration

	// Callbacks for resource events
	onResourceExhausted func(resource string, current, limit interface{})
	onResourceWarning   func(resource string, current, limit interface{}, percentage float64)
}

// NewResourceManager creates a new resource manager with the specified limits
func NewResourceManager(limits ResourceLimits, logger *NetworkMapperLogger) *ResourceManager {
	if logger == nil {
		logger = NewNetworkMapperLogger("resource-manager", LogLevelInfo)
	}

	rm := &ResourceManager{
		limits:          limits,
		logger:          logger,
		connectionSem:   make(chan struct{}, limits.MaxConnections),
		goroutineSem:    make(chan struct{}, limits.MaxGoroutines),
		monitorInterval: 5 * time.Second,
		usage: ResourceUsage{
			StartTime:   time.Now(),
			LastUpdated: time.Now(),
		},
	}

	// Start resource monitoring
	rm.monitorCtx, rm.monitorCancel = context.WithCancel(context.Background())
	go rm.monitorResources()

	return rm
}

// AcquireConnection attempts to acquire a connection slot
func (rm *ResourceManager) AcquireConnection(ctx context.Context) error {
	select {
	case rm.connectionSem <- struct{}{}:
		atomic.AddInt64(&rm.usage.Connections, 1)
		rm.logger.Debug("Connection acquired", "active_connections", atomic.LoadInt64(&rm.usage.Connections))
		return nil
	case <-ctx.Done():
		return NewResourceError("acquire_connection", "context cancelled while waiting for connection slot")
	default:
		// Non-blocking check - connection limit reached
		current := atomic.LoadInt64(&rm.usage.Connections)
		rm.triggerResourceExhausted("connections", current, rm.limits.MaxConnections)
		return NewResourceError("acquire_connection",
			fmt.Sprintf("connection limit reached (%d/%d)", current, rm.limits.MaxConnections),
			"Reduce MaxThreads in scan configuration",
			"Increase MaxConnections in resource limits",
			"Wait for existing connections to complete")
	}
}

// ReleaseConnection releases a connection slot
func (rm *ResourceManager) ReleaseConnection() {
	select {
	case <-rm.connectionSem:
		atomic.AddInt64(&rm.usage.Connections, -1)
		rm.logger.Debug("Connection released", "active_connections", atomic.LoadInt64(&rm.usage.Connections))
	default:
		rm.logger.Warn("Attempted to release connection but none were acquired")
	}
}

// AcquireGoroutine attempts to acquire a goroutine slot
func (rm *ResourceManager) AcquireGoroutine(ctx context.Context) error {
	select {
	case rm.goroutineSem <- struct{}{}:
		rm.logger.Debug("Goroutine slot acquired")
		return nil
	case <-ctx.Done():
		return NewResourceError("acquire_goroutine", "context cancelled while waiting for goroutine slot")
	default:
		// Non-blocking check - goroutine limit reached
		current := runtime.NumGoroutine()
		rm.triggerResourceExhausted("goroutines", current, rm.limits.MaxGoroutines)
		return NewResourceError("acquire_goroutine",
			fmt.Sprintf("goroutine limit reached (%d/%d)", current, rm.limits.MaxGoroutines),
			"Reduce concurrency in scan configuration",
			"Increase MaxGoroutines in resource limits",
			"Wait for existing operations to complete")
	}
}

// ReleaseGoroutine releases a goroutine slot
func (rm *ResourceManager) ReleaseGoroutine() {
	select {
	case <-rm.goroutineSem:
		rm.logger.Debug("Goroutine slot released")
	default:
		rm.logger.Warn("Attempted to release goroutine slot but none were acquired")
	}
}

// CheckMemoryUsage checks if memory usage is within limits
func (rm *ResourceManager) CheckMemoryUsage() error {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	currentMB := float64(m.Alloc) / 1024 / 1024

	rm.mutex.Lock()
	rm.usage.MemoryMB = currentMB
	rm.usage.LastUpdated = time.Now()
	rm.mutex.Unlock()

	if currentMB > rm.limits.MaxMemoryMB {
		rm.triggerResourceExhausted("memory", currentMB, rm.limits.MaxMemoryMB)
		return NewResourceError("memory_check",
			fmt.Sprintf("memory usage exceeded limit (%.2f MB / %.2f MB)", currentMB, rm.limits.MaxMemoryMB),
			"Reduce scan scope (fewer targets or ports)",
			"Increase memory limits",
			"Run garbage collection manually")
	}

	// Warning at 80% usage
	if currentMB > rm.limits.MaxMemoryMB*0.8 {
		percentage := (currentMB / rm.limits.MaxMemoryMB) * 100
		rm.triggerResourceWarning("memory", currentMB, rm.limits.MaxMemoryMB, percentage)
	}

	return nil
}

// ForceGarbageCollection forces garbage collection to free memory
func (rm *ResourceManager) ForceGarbageCollection() {
	rm.logger.Info("Forcing garbage collection to free memory")
	runtime.GC()

	// Check memory usage after GC
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	currentMB := float64(m.Alloc) / 1024 / 1024

	rm.mutex.Lock()
	rm.usage.MemoryMB = currentMB
	rm.usage.LastUpdated = time.Now()
	rm.mutex.Unlock()

	rm.logger.Info("Garbage collection completed", "memory_mb", currentMB)
}

// GetResourceUsage returns current resource usage
func (rm *ResourceManager) GetResourceUsage() ResourceUsage {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	usage := rm.usage
	usage.Goroutines = runtime.NumGoroutine()
	usage.Connections = atomic.LoadInt64(&rm.usage.Connections)

	return usage
}

// GetResourceLimits returns current resource limits
func (rm *ResourceManager) GetResourceLimits() ResourceLimits {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()
	return rm.limits
}

// UpdateLimits updates resource limits (can be used for dynamic adjustment)
func (rm *ResourceManager) UpdateLimits(newLimits ResourceLimits) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	oldLimits := rm.limits
	rm.limits = newLimits

	// Resize semaphores if needed
	if newLimits.MaxConnections != oldLimits.MaxConnections {
		rm.connectionSem = make(chan struct{}, newLimits.MaxConnections)
	}

	if newLimits.MaxGoroutines != oldLimits.MaxGoroutines {
		rm.goroutineSem = make(chan struct{}, newLimits.MaxGoroutines)
	}

	rm.logger.Info("Resource limits updated",
		"max_connections", newLimits.MaxConnections,
		"max_goroutines", newLimits.MaxGoroutines,
		"max_memory_mb", newLimits.MaxMemoryMB)
}

// SetResourceExhaustedCallback sets a callback for when resources are exhausted
func (rm *ResourceManager) SetResourceExhaustedCallback(callback func(resource string, current, limit interface{})) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	rm.onResourceExhausted = callback
}

// SetResourceWarningCallback sets a callback for resource warnings
func (rm *ResourceManager) SetResourceWarningCallback(callback func(resource string, current, limit interface{}, percentage float64)) {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	rm.onResourceWarning = callback
}

// monitorResources continuously monitors system resources
func (rm *ResourceManager) monitorResources() {
	ticker := time.NewTicker(rm.monitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rm.monitorCtx.Done():
			return
		case <-ticker.C:
			rm.updateResourceUsage()
			rm.checkResourceHealth()
		}
	}
}

// updateResourceUsage updates current resource usage statistics
func (rm *ResourceManager) updateResourceUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	rm.mutex.Lock()
	rm.usage.Goroutines = runtime.NumGoroutine()
	rm.usage.MemoryMB = float64(m.Alloc) / 1024 / 1024
	rm.usage.LastUpdated = time.Now()
	rm.mutex.Unlock()

	// Log resource usage periodically
	rm.logger.LogResourceUsage(rm.usage.Goroutines, rm.usage.MemoryMB, rm.usage.OpenFiles)
}

// checkResourceHealth checks if resources are within healthy limits
func (rm *ResourceManager) checkResourceHealth() {
	usage := rm.GetResourceUsage()

	// Check memory usage
	if usage.MemoryMB > rm.limits.MaxMemoryMB*0.9 {
		rm.logger.Warn("High memory usage detected",
			"current_mb", usage.MemoryMB,
			"limit_mb", rm.limits.MaxMemoryMB,
			"percentage", (usage.MemoryMB/rm.limits.MaxMemoryMB)*100)

		// Force garbage collection if memory is very high
		if usage.MemoryMB > rm.limits.MaxMemoryMB*0.95 {
			rm.ForceGarbageCollection()
		}
	}

	// Check goroutine count
	if usage.Goroutines > rm.limits.MaxGoroutines*9/10 {
		rm.logger.Warn("High goroutine count detected",
			"current", usage.Goroutines,
			"limit", rm.limits.MaxGoroutines,
			"percentage", (float64(usage.Goroutines)/float64(rm.limits.MaxGoroutines))*100)
	}

	// Check connection count
	if usage.Connections > int64(rm.limits.MaxConnections)*9/10 {
		rm.logger.Warn("High connection count detected",
			"current", usage.Connections,
			"limit", rm.limits.MaxConnections,
			"percentage", (float64(usage.Connections)/float64(rm.limits.MaxConnections))*100)
	}
}

// triggerResourceExhausted triggers the resource exhausted callback
func (rm *ResourceManager) triggerResourceExhausted(resource string, current, limit interface{}) {
	rm.mutex.RLock()
	callback := rm.onResourceExhausted
	rm.mutex.RUnlock()

	if callback != nil {
		callback(resource, current, limit)
	}
}

// triggerResourceWarning triggers the resource warning callback
func (rm *ResourceManager) triggerResourceWarning(resource string, current, limit interface{}, percentage float64) {
	rm.mutex.RLock()
	callback := rm.onResourceWarning
	rm.mutex.RUnlock()

	if callback != nil {
		callback(resource, current, limit, percentage)
	}
}

// Close stops resource monitoring and cleans up
func (rm *ResourceManager) Close() error {
	if rm.monitorCancel != nil {
		rm.monitorCancel()
	}

	rm.logger.Info("Resource manager stopped")
	return nil
}

// WithResourceManagement wraps a function with resource management
func (rm *ResourceManager) WithResourceManagement(ctx context.Context, operation string, fn func() error) error {
	// Check memory before starting
	if err := rm.CheckMemoryUsage(); err != nil {
		return WrapError(err, operation, "", 0)
	}

	// Acquire goroutine slot
	if err := rm.AcquireGoroutine(ctx); err != nil {
		return WrapError(err, operation, "", 0)
	}
	defer rm.ReleaseGoroutine()

	// Execute the function
	return fn()
}

// WithConnectionManagement wraps a function that needs network connections
func (rm *ResourceManager) WithConnectionManagement(ctx context.Context, operation, target string, port int, fn func() error) error {
	// Acquire connection slot
	if err := rm.AcquireConnection(ctx); err != nil {
		return WrapError(err, operation, target, port)
	}
	defer rm.ReleaseConnection()

	// Execute the function
	return fn()
}

// EstimateResourceRequirements estimates resource requirements for a scan configuration
func (rm *ResourceManager) EstimateResourceRequirements(config ScanConfig) (ResourceEstimate, error) {
	// Calculate total operations
	totalTargets := len(config.Targets)
	totalPorts := len(config.Ports)
	for _, portRange := range config.PortRanges {
		totalPorts += portRange.End - portRange.Start + 1
	}

	totalOperations := totalTargets * totalPorts

	// Estimate based on configuration
	estimate := ResourceEstimate{
		TotalOperations:   totalOperations,
		EstimatedDuration: time.Duration(totalOperations/config.MaxThreads) * config.Timeout,
		PeakGoroutines:    config.MaxThreads + 10, // Add overhead
		PeakConnections:   config.MaxThreads,
		EstimatedMemoryMB: float64(totalOperations) * 0.001, // 1KB per operation estimate
	}

	// Check if requirements exceed limits
	var issues []string
	if estimate.PeakGoroutines > rm.limits.MaxGoroutines {
		issues = append(issues, fmt.Sprintf("goroutines: need %d, limit %d", estimate.PeakGoroutines, rm.limits.MaxGoroutines))
	}
	if estimate.PeakConnections > rm.limits.MaxConnections {
		issues = append(issues, fmt.Sprintf("connections: need %d, limit %d", estimate.PeakConnections, rm.limits.MaxConnections))
	}
	if estimate.EstimatedMemoryMB > rm.limits.MaxMemoryMB {
		issues = append(issues, fmt.Sprintf("memory: need %.2f MB, limit %.2f MB", estimate.EstimatedMemoryMB, rm.limits.MaxMemoryMB))
	}

	if len(issues) > 0 {
		return estimate, NewResourceError("resource_estimation",
			fmt.Sprintf("scan may exceed resource limits: %s", strings.Join(issues, "; ")),
			"Reduce scan scope (fewer targets or ports)",
			"Increase resource limits",
			"Use smaller MaxThreads value")
	}

	return estimate, nil
}

// ResourceEstimate contains estimated resource requirements
type ResourceEstimate struct {
	TotalOperations   int
	EstimatedDuration time.Duration
	PeakGoroutines    int
	PeakConnections   int
	EstimatedMemoryMB float64
}
