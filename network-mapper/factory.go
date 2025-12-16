package networkmapper

import (
	"log"
	"time"
)

// NewScannerEngine creates a new scanner engine with default components
// This is a convenience function that sets up all the required components
func NewScannerEngine() ScannerEngine {
	// Initialize file system integration
	configManager := NewConfigManager()
	if err := configManager.InitializeDefaultFiles(); err != nil {
		log.Printf("Warning: Failed to initialize default files: %v", err)
	}

	// Create default components with reasonable defaults
	logger := log.Default()
	portScanner := NewDefaultPortScanner(5*time.Second, 3, logger)
	serviceDetector := NewDefaultServiceDetector(10*time.Second, 2, logger)
	osFingerprinter := NewDefaultOSFingerprinter(15*time.Second, 2, logger)
	progressMonitor := NewDefaultProgressMonitor(nil) // No callback by default
	targetResolver := NewTargetResolver()

	// Create and return the concurrent scanner engine
	return NewConcurrentScannerEngine(
		portScanner,
		serviceDetector,
		osFingerprinter,
		targetResolver,
		progressMonitor,
		logger,
	)
}
