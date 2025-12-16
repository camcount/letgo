package networkmapper

import (
	"context"
)

// ScannerEngine is the main interface for the network scanning engine
type ScannerEngine interface {
	// Scan performs a network scan with the given configuration
	Scan(ctx context.Context, config ScanConfig) (*ScanResult, error)

	// Pause suspends the current scan
	Pause() error

	// Resume continues a paused scan
	Resume() error

	// Stop terminates the current scan
	Stop() error

	// GetProgress returns current scan progress information
	GetProgress() ProgressInfo
}

// PortScanner handles port scanning operations
type PortScanner interface {
	// ScanPort scans a single port on a target
	ScanPort(ctx context.Context, target string, port int, scanType ScanType) PortResult

	// ScanPorts scans multiple ports on a target
	ScanPorts(ctx context.Context, target string, ports []int, scanType ScanType) []PortResult
}

// ServiceDetector handles service detection and banner grabbing
type ServiceDetector interface {
	// DetectService attempts to identify the service running on a port
	DetectService(ctx context.Context, target string, port int) ServiceInfo

	// GrabBanner attempts to grab a service banner from a port
	GrabBanner(ctx context.Context, target string, port int) (string, error)
}

// OSFingerprinter handles operating system detection
type OSFingerprinter interface {
	// DetectOS attempts to identify the operating system of a target
	DetectOS(ctx context.Context, target string, openPorts []int) OSInfo
}

// ResultManager handles result formatting, storage, and export
type ResultManager interface {
	// SaveResults saves scan results to a file in the specified format
	SaveResults(results *ScanResult, format OutputFormat, filename string) error

	// ExportResults exports scan results to bytes in the specified format
	ExportResults(results *ScanResult, format OutputFormat) ([]byte, error)

	// LoadResults loads scan results from a file
	LoadResults(filename string) (*ScanResult, error)

	// ExportWebServicesForScanning exports discovered web services for endpoint scanning
	ExportWebServicesForScanning(results *ScanResult, outputPath string) error

	// ExportTargetsForBruteForce exports discovered services for brute force attacks
	ExportTargetsForBruteForce(results *ScanResult, outputPath string) error

	// ExportTargetsForDDoS exports discovered web services for DDoS testing
	ExportTargetsForDDoS(results *ScanResult, outputPath string) error
}

// ProfileManager handles scan profile management
type ProfileManager interface {
	// GetProfile retrieves a scan profile by name
	GetProfile(name string) (*ScanProfile, error)

	// SaveProfile saves a custom scan profile
	SaveProfile(profile ScanProfile) error

	// ListProfiles returns all available scan profiles
	ListProfiles() []ScanProfile

	// DeleteProfile removes a custom scan profile
	DeleteProfile(name string) error
}

// ProgressMonitor handles real-time progress tracking and reporting
type ProgressMonitor interface {
	// Start begins progress monitoring
	Start(totalHosts, totalPorts int)

	// UpdateProgress updates the current progress
	UpdateProgress(hostsScanned, portsScanned int, currentTarget string, currentPort int)

	// Stop ends progress monitoring
	Stop()

	// GetProgress returns current progress information
	GetProgress() ProgressInfo
}

// TargetResolver handles target resolution and expansion
type TargetResolver interface {
	// ResolveTargets resolves and expands target specifications
	ResolveTargets(targets []string) ([]NetworkTarget, error)

	// ExpandCIDR expands a CIDR range to individual IP addresses
	ExpandCIDR(cidr string) ([]string, error)

	// ResolveHostname resolves a hostname to IP addresses
	ResolveHostname(hostname string) ([]string, error)
}
