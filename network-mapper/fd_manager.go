package networkmapper

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// FileDescriptorManager manages file descriptors for network connections
type FileDescriptorManager struct {
	// Limits and tracking
	maxOpenFiles   int
	currentOpenFDs int64
	fdSemaphore    chan struct{}

	// Monitoring
	logger          *NetworkMapperLogger
	monitorInterval time.Duration
	monitorCtx      context.Context
	monitorCancel   context.CancelFunc

	// Statistics
	totalAcquired   int64
	totalReleased   int64
	peakUsage       int64
	acquisitionTime int64 // Total time spent acquiring FDs (nanoseconds)

	// Cleanup tracking
	activeConnections map[string]*ConnectionInfo
	connectionsMutex  sync.RWMutex

	// Configuration
	cleanupInterval   time.Duration
	connectionTimeout time.Duration
}

// ConnectionInfo tracks information about active connections
type ConnectionInfo struct {
	Target    string
	Port      int
	StartTime time.Time
	LastUsed  time.Time
	ConnType  string // "tcp", "udp"
}

// NewFileDescriptorManager creates a new file descriptor manager
func NewFileDescriptorManager(maxOpenFiles int, logger *NetworkMapperLogger) *FileDescriptorManager {
	if logger == nil {
		logger = NewNetworkMapperLogger("fd-manager", LogLevelInfo)
	}

	if maxOpenFiles <= 0 {
		maxOpenFiles = 1000 // Default limit
	}

	fdm := &FileDescriptorManager{
		maxOpenFiles:      maxOpenFiles,
		fdSemaphore:       make(chan struct{}, maxOpenFiles),
		logger:            logger,
		monitorInterval:   10 * time.Second,
		activeConnections: make(map[string]*ConnectionInfo),
		cleanupInterval:   30 * time.Second,
		connectionTimeout: 5 * time.Minute,
	}

	// Start monitoring
	fdm.monitorCtx, fdm.monitorCancel = context.WithCancel(context.Background())
	go fdm.monitorFileDescriptors()
	go fdm.cleanupStaleConnections()

	return fdm
}

// AcquireFileDescriptor attempts to acquire a file descriptor slot
func (fdm *FileDescriptorManager) AcquireFileDescriptor(ctx context.Context, target string, port int, connType string) error {
	startTime := time.Now()

	select {
	case fdm.fdSemaphore <- struct{}{}:
		// Successfully acquired FD slot
		current := atomic.AddInt64(&fdm.currentOpenFDs, 1)
		atomic.AddInt64(&fdm.totalAcquired, 1)

		// Update peak usage
		for {
			peak := atomic.LoadInt64(&fdm.peakUsage)
			if current <= peak || atomic.CompareAndSwapInt64(&fdm.peakUsage, peak, current) {
				break
			}
		}

		// Track acquisition time
		acquisitionDuration := time.Since(startTime)
		atomic.AddInt64(&fdm.acquisitionTime, acquisitionDuration.Nanoseconds())

		// Register the connection
		fdm.registerConnection(target, port, connType)

		fdm.logger.Debug("File descriptor acquired",
			"target", target,
			"port", port,
			"type", connType,
			"current_fds", current,
			"acquisition_time", acquisitionDuration)

		return nil

	case <-ctx.Done():
		return NewResourceError("acquire_fd", "context cancelled while waiting for file descriptor")

	default:
		// Non-blocking check - FD limit reached
		current := atomic.LoadInt64(&fdm.currentOpenFDs)
		fdm.logger.Warn("File descriptor limit reached",
			"current", current,
			"limit", fdm.maxOpenFiles,
			"target", target,
			"port", port)

		return NewResourceError("acquire_fd",
			fmt.Sprintf("file descriptor limit reached (%d/%d)", current, fdm.maxOpenFiles),
			"Reduce concurrent connections",
			"Increase file descriptor limits",
			"Wait for existing connections to close")
	}
}

// ReleaseFileDescriptor releases a file descriptor slot
func (fdm *FileDescriptorManager) ReleaseFileDescriptor(target string, port int) {
	select {
	case <-fdm.fdSemaphore:
		current := atomic.AddInt64(&fdm.currentOpenFDs, -1)
		atomic.AddInt64(&fdm.totalReleased, 1)

		// Unregister the connection
		fdm.unregisterConnection(target, port)

		fdm.logger.Debug("File descriptor released",
			"target", target,
			"port", port,
			"current_fds", current)

	default:
		fdm.logger.Warn("Attempted to release file descriptor but none were acquired",
			"target", target,
			"port", port)
	}
}

// registerConnection registers an active connection for tracking
func (fdm *FileDescriptorManager) registerConnection(target string, port int, connType string) {
	key := fmt.Sprintf("%s:%d:%s", target, port, connType)
	now := time.Now()

	fdm.connectionsMutex.Lock()
	fdm.activeConnections[key] = &ConnectionInfo{
		Target:    target,
		Port:      port,
		StartTime: now,
		LastUsed:  now,
		ConnType:  connType,
	}
	fdm.connectionsMutex.Unlock()
}

// unregisterConnection removes a connection from tracking
func (fdm *FileDescriptorManager) unregisterConnection(target string, port int) {
	// Try to find and remove the connection (we don't know the type, so try common ones)
	keys := []string{
		fmt.Sprintf("%s:%d:tcp", target, port),
		fmt.Sprintf("%s:%d:udp", target, port),
	}

	fdm.connectionsMutex.Lock()
	for _, key := range keys {
		delete(fdm.activeConnections, key)
	}
	fdm.connectionsMutex.Unlock()
}

// UpdateConnectionActivity updates the last used time for a connection
func (fdm *FileDescriptorManager) UpdateConnectionActivity(target string, port int, connType string) {
	key := fmt.Sprintf("%s:%d:%s", target, port, connType)

	fdm.connectionsMutex.Lock()
	if conn, exists := fdm.activeConnections[key]; exists {
		conn.LastUsed = time.Now()
	}
	fdm.connectionsMutex.Unlock()
}

// GetFileDescriptorStats returns current file descriptor statistics
func (fdm *FileDescriptorManager) GetFileDescriptorStats() FileDescriptorStats {
	current := atomic.LoadInt64(&fdm.currentOpenFDs)
	totalAcquired := atomic.LoadInt64(&fdm.totalAcquired)
	totalReleased := atomic.LoadInt64(&fdm.totalReleased)
	peak := atomic.LoadInt64(&fdm.peakUsage)
	totalAcquisitionTime := atomic.LoadInt64(&fdm.acquisitionTime)

	var avgAcquisitionTime time.Duration
	if totalAcquired > 0 {
		avgAcquisitionTime = time.Duration(totalAcquisitionTime / totalAcquired)
	}

	fdm.connectionsMutex.RLock()
	activeConnections := len(fdm.activeConnections)
	fdm.connectionsMutex.RUnlock()

	return FileDescriptorStats{
		CurrentOpenFDs:     current,
		MaxOpenFDs:         int64(fdm.maxOpenFiles),
		TotalAcquired:      totalAcquired,
		TotalReleased:      totalReleased,
		PeakUsage:          peak,
		ActiveConnections:  int64(activeConnections),
		AvgAcquisitionTime: avgAcquisitionTime,
		UtilizationPercent: float64(current) / float64(fdm.maxOpenFiles) * 100,
	}
}

// monitorFileDescriptors continuously monitors file descriptor usage
func (fdm *FileDescriptorManager) monitorFileDescriptors() {
	ticker := time.NewTicker(fdm.monitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-fdm.monitorCtx.Done():
			return
		case <-ticker.C:
			fdm.logFileDescriptorStats()
			fdm.checkFileDescriptorHealth()
		}
	}
}

// logFileDescriptorStats logs current file descriptor statistics
func (fdm *FileDescriptorManager) logFileDescriptorStats() {
	stats := fdm.GetFileDescriptorStats()

	fdm.logger.LogResourceUsage(
		runtime.NumGoroutine(),
		float64(stats.CurrentOpenFDs),
		int(stats.ActiveConnections))
}

// checkFileDescriptorHealth checks if file descriptor usage is healthy
func (fdm *FileDescriptorManager) checkFileDescriptorHealth() {
	stats := fdm.GetFileDescriptorStats()

	// Warn if utilization is high
	if stats.UtilizationPercent > 80 {
		fdm.logger.Warn("High file descriptor utilization",
			"current", stats.CurrentOpenFDs,
			"max", stats.MaxOpenFDs,
			"utilization_percent", stats.UtilizationPercent,
			"active_connections", stats.ActiveConnections)
	}

	// Check for potential leaks (more tracked connections than FDs)
	if stats.ActiveConnections > stats.CurrentOpenFDs {
		fdm.logger.Warn("Potential connection tracking inconsistency",
			"tracked_connections", stats.ActiveConnections,
			"current_fds", stats.CurrentOpenFDs)
	}
}

// cleanupStaleConnections removes stale connection tracking entries
func (fdm *FileDescriptorManager) cleanupStaleConnections() {
	ticker := time.NewTicker(fdm.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-fdm.monitorCtx.Done():
			return
		case <-ticker.C:
			fdm.performConnectionCleanup()
		}
	}
}

// performConnectionCleanup removes connections that haven't been used recently
func (fdm *FileDescriptorManager) performConnectionCleanup() {
	now := time.Now()
	staleConnections := make([]string, 0)

	fdm.connectionsMutex.RLock()
	for key, conn := range fdm.activeConnections {
		if now.Sub(conn.LastUsed) > fdm.connectionTimeout {
			staleConnections = append(staleConnections, key)
		}
	}
	fdm.connectionsMutex.RUnlock()

	if len(staleConnections) > 0 {
		fdm.connectionsMutex.Lock()
		for _, key := range staleConnections {
			delete(fdm.activeConnections, key)
		}
		fdm.connectionsMutex.Unlock()

		fdm.logger.Info("Cleaned up stale connection tracking entries",
			"count", len(staleConnections))
	}
}

// GetActiveConnections returns information about currently active connections
func (fdm *FileDescriptorManager) GetActiveConnections() []ConnectionInfo {
	fdm.connectionsMutex.RLock()
	defer fdm.connectionsMutex.RUnlock()

	connections := make([]ConnectionInfo, 0, len(fdm.activeConnections))
	for _, conn := range fdm.activeConnections {
		connections = append(connections, *conn)
	}

	return connections
}

// SetMaxOpenFiles updates the maximum number of open files
func (fdm *FileDescriptorManager) SetMaxOpenFiles(maxFiles int) error {
	if maxFiles <= 0 {
		return fmt.Errorf("maxFiles must be positive, got %d", maxFiles)
	}

	current := atomic.LoadInt64(&fdm.currentOpenFDs)
	if int64(maxFiles) < current {
		return fmt.Errorf("cannot set limit (%d) below current usage (%d)", maxFiles, current)
	}

	fdm.maxOpenFiles = maxFiles
	fdm.fdSemaphore = make(chan struct{}, maxFiles)

	fdm.logger.Info("Updated file descriptor limit", "new_limit", maxFiles)
	return nil
}

// Close stops monitoring and cleans up resources
func (fdm *FileDescriptorManager) Close() error {
	if fdm.monitorCancel != nil {
		fdm.monitorCancel()
	}

	// Log final statistics
	stats := fdm.GetFileDescriptorStats()
	fdm.logger.Info("File descriptor manager stopped",
		"final_open_fds", stats.CurrentOpenFDs,
		"total_acquired", stats.TotalAcquired,
		"total_released", stats.TotalReleased,
		"peak_usage", stats.PeakUsage)

	return nil
}

// FileDescriptorStats contains file descriptor usage statistics
type FileDescriptorStats struct {
	CurrentOpenFDs     int64
	MaxOpenFDs         int64
	TotalAcquired      int64
	TotalReleased      int64
	PeakUsage          int64
	ActiveConnections  int64
	AvgAcquisitionTime time.Duration
	UtilizationPercent float64
}

// WithFileDescriptor executes a function with file descriptor management
func (fdm *FileDescriptorManager) WithFileDescriptor(ctx context.Context, target string, port int, connType string, fn func() error) error {
	// Acquire file descriptor
	if err := fdm.AcquireFileDescriptor(ctx, target, port, connType); err != nil {
		return err
	}
	defer fdm.ReleaseFileDescriptor(target, port)

	// Update activity before and after the operation
	fdm.UpdateConnectionActivity(target, port, connType)
	defer fdm.UpdateConnectionActivity(target, port, connType)

	// Execute the function
	return fn()
}
