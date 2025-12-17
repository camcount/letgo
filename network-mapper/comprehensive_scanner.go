package networkmapper

import (
	"os"
	"path/filepath"
	"time"
)

// ComprehensiveScannerConfig contains configuration for creating a comprehensive scanner
type ComprehensiveScannerConfig struct {
	// Resource limits
	ResourceLimits ResourceLimits

	// Logging configuration
	LogLevel  LogLevel
	LogToFile bool
	LogDir    string

	// Scanner timeouts
	PortTimeout    time.Duration
	ServiceTimeout time.Duration
	OSTimeout      time.Duration

	// Retry configuration
	MaxRetries int

	// Component configuration
	EnableOptimized bool
}

// DefaultComprehensiveScannerConfig returns a default configuration for comprehensive scanning
func DefaultComprehensiveScannerConfig() ComprehensiveScannerConfig {
	return ComprehensiveScannerConfig{
		ResourceLimits:  DefaultResourceLimits(),
		LogLevel:        LogLevelInfo,
		LogToFile:       true,
		LogDir:          filepath.Join("application", "data", "network-mapper", "logs"),
		PortTimeout:     5 * time.Second,
		ServiceTimeout:  10 * time.Second,
		OSTimeout:       15 * time.Second,
		MaxRetries:      3,
		EnableOptimized: true,
	}
}

// ComprehensiveScanner provides a fully integrated scanner with comprehensive error handling
type ComprehensiveScanner struct {
	Engine          ScannerEngine
	Logger          *NetworkMapperLogger
	ErrorHandler    *ErrorHandler
	ResourceManager *ResourceManager
}

// NewComprehensiveScanner creates a new comprehensive scanner with all error handling integrated
func NewComprehensiveScanner(config ComprehensiveScannerConfig) (*ComprehensiveScanner, error) {
	// Create logger
	var logger *NetworkMapperLogger
	var err error

	if config.LogToFile && config.LogDir != "" {
		logger, err = NewNetworkMapperLoggerWithFile("comprehensive-scanner", config.LogLevel, config.LogDir)
		if err != nil {
			// Fallback to console-only logging
			logger = NewNetworkMapperLogger("comprehensive-scanner", config.LogLevel)
			logger.Warn("Failed to enable file logging, using console only", "error", err)
		}
	} else {
		logger = NewNetworkMapperLogger("comprehensive-scanner", config.LogLevel)
	}

	// Create resource manager
	resourceManager := NewResourceManager(config.ResourceLimits, logger)

	// Create error handler
	errorHandler := NewErrorHandler(logger, resourceManager)

	// Create components with error handling
	portScanner := createPortScannerWithErrorHandling(config, logger, errorHandler, resourceManager)
	serviceDetector := createServiceDetectorWithErrorHandling(config, logger, errorHandler)
	osFingerprinter := createOSFingerprinterWithErrorHandling(config, logger, errorHandler)
	targetResolver := createTargetResolverWithErrorHandling(logger, errorHandler)
	progressMonitor := createProgressMonitorWithErrorHandling(logger)

	// Create engine with comprehensive error handling
	ipResolver := NewIPResolver()
	protectionDetector := NewProtectionDetector()
	infrastructureAnalyzer := NewInfrastructureAnalyzer()

	engine := NewConcurrentScannerEngineWithErrorHandling(
		portScanner,
		serviceDetector,
		osFingerprinter,
		targetResolver,
		progressMonitor,
		ipResolver,
		protectionDetector,
		infrastructureAnalyzer,
		logger,
		errorHandler,
		resourceManager,
	)

	return &ComprehensiveScanner{
		Engine:          engine,
		Logger:          logger,
		ErrorHandler:    errorHandler,
		ResourceManager: resourceManager,
	}, nil
}

// createPortScannerWithErrorHandling creates a port scanner with comprehensive error handling
func createPortScannerWithErrorHandling(config ComprehensiveScannerConfig, logger *NetworkMapperLogger, errorHandler *ErrorHandler, resourceManager *ResourceManager) PortScanner {
	if config.EnableOptimized {
		return NewOptimizedPortScanner(config.PortTimeout, config.MaxRetries, resourceManager, logger)
	}

	return NewDefaultPortScannerWithErrorHandling(config.PortTimeout, config.MaxRetries, logger, errorHandler)
}

// createServiceDetectorWithErrorHandling creates a service detector with error handling
func createServiceDetectorWithErrorHandling(config ComprehensiveScannerConfig, logger *NetworkMapperLogger, errorHandler *ErrorHandler) ServiceDetector {
	// Use standard logger for backward compatibility with existing ServiceDetector
	stdLogger := logger.ToStandardLogger()
	return NewDefaultServiceDetector(config.ServiceTimeout, config.MaxRetries, stdLogger)
}

// createOSFingerprinterWithErrorHandling creates an OS fingerprinter with error handling
func createOSFingerprinterWithErrorHandling(config ComprehensiveScannerConfig, logger *NetworkMapperLogger, errorHandler *ErrorHandler) OSFingerprinter {
	// Use standard logger for backward compatibility with existing OSFingerprinter
	stdLogger := logger.ToStandardLogger()
	return NewDefaultOSFingerprinter(config.OSTimeout, config.MaxRetries, stdLogger)
}

// createTargetResolverWithErrorHandling creates a target resolver with error handling
func createTargetResolverWithErrorHandling(logger *NetworkMapperLogger, errorHandler *ErrorHandler) TargetResolver {
	return NewTargetResolver()
}

// createProgressMonitorWithErrorHandling creates a progress monitor with error handling
func createProgressMonitorWithErrorHandling(logger *NetworkMapperLogger) ProgressMonitor {
	// Create a progress callback that uses the logger
	progressCallback := func(progress ProgressInfo) {
		logger.Debug("Scan progress update",
			"hosts_scanned", progress.HostsScanned,
			"hosts_total", progress.HostsTotal,
			"ports_scanned", progress.PortsScanned,
			"ports_total", progress.PortsTotal,
			"elapsed_time", progress.ElapsedTime,
			"estimated_time", progress.EstimatedTime,
			"scan_rate", progress.ScanRate)
	}

	return NewDefaultProgressMonitor(progressCallback)
}

// Close closes all resources and stops monitoring
func (cs *ComprehensiveScanner) Close() error {
	var lastErr error

	// Close resource manager
	if err := cs.ResourceManager.Close(); err != nil {
		lastErr = err
		cs.Logger.Error("Failed to close resource manager", "error", err)
	}

	// Close logger
	if err := cs.Logger.Close(); err != nil {
		lastErr = err
		// Can't log this error since logger is being closed
	}

	return lastErr
}

// GetErrorStatistics returns current error statistics
func (cs *ComprehensiveScanner) GetErrorStatistics() ErrorStatisticsSnapshot {
	return cs.ErrorHandler.GetErrorStatistics()
}

// GetResourceUsage returns current resource usage
func (cs *ComprehensiveScanner) GetResourceUsage() ResourceUsage {
	return cs.ResourceManager.GetResourceUsage()
}

// SetResourceLimits updates resource limits dynamically
func (cs *ComprehensiveScanner) SetResourceLimits(limits ResourceLimits) {
	cs.ResourceManager.UpdateLimits(limits)
}

// SetLogLevel updates the logging level
func (cs *ComprehensiveScanner) SetLogLevel(level LogLevel) {
	cs.Logger.SetLevel(level)
}

// EnableFileLogging enables logging to file
func (cs *ComprehensiveScanner) EnableFileLogging(logDir string) error {
	return cs.Logger.EnableFileLogging(logDir)
}

// DisableFileLogging disables file logging
func (cs *ComprehensiveScanner) DisableFileLogging() {
	cs.Logger.DisableFileLogging()
}

// ValidateConfiguration validates a scan configuration before execution
func (cs *ComprehensiveScanner) ValidateConfiguration(config ScanConfig) error {
	return ValidateComprehensive(config, cs.ResourceManager.GetResourceLimits())
}

// EstimateResourceRequirements estimates resource requirements for a scan
func (cs *ComprehensiveScanner) EstimateResourceRequirements(config ScanConfig) (ResourceEstimate, error) {
	return cs.ResourceManager.EstimateResourceRequirements(config)
}

// SetResourceExhaustedCallback sets a callback for resource exhaustion events
func (cs *ComprehensiveScanner) SetResourceExhaustedCallback(callback func(resource string, current, limit interface{})) {
	cs.ResourceManager.SetResourceExhaustedCallback(callback)
}

// SetResourceWarningCallback sets a callback for resource warning events
func (cs *ComprehensiveScanner) SetResourceWarningCallback(callback func(resource string, current, limit interface{}, percentage float64)) {
	cs.ResourceManager.SetResourceWarningCallback(callback)
}

// CreateDefaultComprehensiveScanner creates a comprehensive scanner with default settings
func CreateDefaultComprehensiveScanner() (*ComprehensiveScanner, error) {
	config := DefaultComprehensiveScannerConfig()

	// Ensure log directory exists
	if config.LogToFile && config.LogDir != "" {
		if err := os.MkdirAll(config.LogDir, 0755); err != nil {
			// Disable file logging if directory creation fails
			config.LogToFile = false
		}
	}

	return NewComprehensiveScanner(config)
}
