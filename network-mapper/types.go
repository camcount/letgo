package networkmapper

import (
	"net"
	"time"
)

// ScanType represents different types of port scans
type ScanType int

const (
	ScanTypeTCPSYN ScanType = iota
	ScanTypeTCPConnect
	ScanTypeUDP
)

// String returns the string representation of ScanType
func (st ScanType) String() string {
	switch st {
	case ScanTypeTCPSYN:
		return "TCP SYN"
	case ScanTypeTCPConnect:
		return "TCP Connect"
	case ScanTypeUDP:
		return "UDP"
	default:
		return "Unknown"
	}
}

// PortState represents the state of a scanned port
type PortState int

const (
	PortOpen PortState = iota
	PortClosed
	PortFiltered
)

// String returns the string representation of PortState
func (ps PortState) String() string {
	switch ps {
	case PortOpen:
		return "open"
	case PortClosed:
		return "closed"
	case PortFiltered:
		return "filtered"
	default:
		return "unknown"
	}
}

// HostStatus represents the status of a target host
type HostStatus int

const (
	HostUp HostStatus = iota
	HostDown
	HostUnknown
)

// String returns the string representation of HostStatus
func (hs HostStatus) String() string {
	switch hs {
	case HostUp:
		return "up"
	case HostDown:
		return "down"
	case HostUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

// OutputFormat represents different output formats for scan results
type OutputFormat int

const (
	OutputFormatJSON OutputFormat = iota
	OutputFormatXML
	OutputFormatText
)

// String returns the string representation of OutputFormat
func (of OutputFormat) String() string {
	switch of {
	case OutputFormatJSON:
		return "json"
	case OutputFormatXML:
		return "xml"
	case OutputFormatText:
		return "text"
	default:
		return "text"
	}
}

// ProgressCallback is a function type for progress updates
type ProgressCallback func(ProgressInfo)

// PortRange represents a range of ports to scan
type PortRange struct {
	Start int
	End   int
}

// ScanConfig contains all configuration parameters for a network scan
type ScanConfig struct {
	Targets       []string         `json:"targets" xml:"targets"`               // IP addresses, hostnames, or CIDR ranges
	Ports         []int            `json:"ports" xml:"ports"`                   // Specific ports to scan
	PortRanges    []PortRange      `json:"port_ranges" xml:"port_ranges"`       // Port ranges to scan
	ScanType      ScanType         `json:"scan_type" xml:"scan_type"`           // TCP SYN, TCP Connect, UDP, etc.
	ScanProfile   ScanProfile      `json:"scan_profile" xml:"scan_profile"`     // Quick, comprehensive, stealth, vulnerability
	ServiceDetect bool             `json:"service_detect" xml:"service_detect"` // Enable service detection
	OSDetect      bool             `json:"os_detect" xml:"os_detect"`           // Enable OS fingerprinting
	MaxThreads    int              `json:"max_threads" xml:"max_threads"`       // Concurrent scanning threads
	Timeout       time.Duration    `json:"timeout" xml:"timeout"`               // Per-port timeout
	OutputFormat  OutputFormat     `json:"output_format" xml:"output_format"`   // JSON, XML, text
	OutputFile    string           `json:"output_file" xml:"output_file"`       // Output file path
	OnProgress    ProgressCallback `json:"-" xml:"-"`                           // Progress update callback (not serialized)
}

// ServiceInfo contains information about a detected service
type ServiceInfo struct {
	Name       string     `json:"name" xml:"name"`             // Service name (e.g., "http", "ssh", "mysql")
	Version    string     `json:"version" xml:"version"`       // Service version
	Product    string     `json:"product" xml:"product"`       // Product name
	ExtraInfo  []KeyValue `json:"extra_info" xml:"extra_info"` // Additional service details
	Confidence float64    `json:"confidence" xml:"confidence"` // Detection confidence (0-100)
	Banner     string     `json:"banner" xml:"banner"`         // Service banner if available
}

// KeyValue represents a key-value pair for XML serialization
type KeyValue struct {
	Key   string `json:"key" xml:"key"`
	Value string `json:"value" xml:"value"`
}

// PortResult contains the result of scanning a single port
type PortResult struct {
	Port         int           // Port number
	Protocol     string        // TCP or UDP
	State        PortState     // Open, Closed, Filtered
	Service      ServiceInfo   // Detected service information
	Banner       string        // Service banner if available
	ResponseTime time.Duration // Response time for the port scan
}

// OSMatch represents a possible OS match
type OSMatch struct {
	Name       string  // OS name
	Version    string  // OS version
	Confidence float64 // Match confidence
}

// OSInfo contains operating system detection results
type OSInfo struct {
	Family     string    // OS family (Linux, Windows, etc.)
	Version    string    // OS version
	Matches    []OSMatch // All possible matches
	Confidence float64   // Overall confidence
}

// HostResult contains the scan results for a single host
type HostResult struct {
	Target       string        // Target IP or hostname
	Status       HostStatus    // Up, Down, Unknown
	Ports        []PortResult  // Scan results for each port
	OS           OSInfo        // OS detection results
	ResponseTime time.Duration // Host response time
}

// ScanStatistics contains statistics about the scan
type ScanStatistics struct {
	HostsScanned  int           // Number of hosts scanned
	HostsTotal    int           // Total number of hosts to scan
	PortsScanned  int           // Number of ports scanned
	PortsTotal    int           // Total number of ports to scan
	OpenPorts     int           // Number of open ports found
	ClosedPorts   int           // Number of closed ports found
	FilteredPorts int           // Number of filtered ports found
	StartTime     time.Time     // Scan start time
	EndTime       time.Time     // Scan end time
	ElapsedTime   time.Duration // Total elapsed time
	ScanRate      float64       // Ports per second
}

// ScanResult contains the complete results of a network scan
type ScanResult struct {
	Timestamp  time.Time      // When the scan was performed
	ScanConfig ScanConfig     // Configuration used for the scan
	Hosts      []HostResult   // Results for each scanned host
	Statistics ScanStatistics // Scan statistics
}

// ProgressInfo contains real-time progress information
type ProgressInfo struct {
	HostsScanned  int           // Number of hosts scanned so far
	HostsTotal    int           // Total number of hosts to scan
	PortsScanned  int           // Number of ports scanned so far
	PortsTotal    int           // Total number of ports to scan
	ElapsedTime   time.Duration // Time elapsed since scan start
	EstimatedTime time.Duration // Estimated time remaining
	ScanRate      float64       // Current scan rate (ports per second)
	CurrentTarget string        // Currently scanning target
	CurrentPort   int           // Currently scanning port
}

// ScanProfile represents predefined scan configurations
type ScanProfile struct {
	Name        string        // Profile name
	Description string        // Profile description
	Ports       []int         // Ports to scan
	ScanType    ScanType      // Scan type to use
	Timing      TimingProfile // Timing configuration
	Options     ScanOptions   // Additional options
}

// TimingProfile contains timing-related configuration
type TimingProfile struct {
	ConnectTimeout    time.Duration // Connection timeout
	ReadTimeout       time.Duration // Read timeout
	DelayBetweenPorts time.Duration // Delay between port scans
	DelayBetweenHosts time.Duration // Delay between host scans
	MaxRetries        int           // Maximum retry attempts
}

// ScanOptions contains various scan options and flags
type ScanOptions struct {
	ServiceDetection bool // Enable service detection
	OSDetection      bool // Enable OS detection
	AggressiveMode   bool // Enable aggressive scanning
	StealthMode      bool // Enable stealth scanning
	FragmentPackets  bool // Fragment packets for evasion
}

// ServiceSignature represents a service detection signature
type ServiceSignature struct {
	Port        int    // Port number
	Protocol    string // TCP or UDP
	Probe       []byte // Probe data to send
	Match       string // Regular expression to match response
	ServiceName string // Service name if matched
	Version     string // Version extraction pattern
}

// NetworkTarget represents a resolved network target
type NetworkTarget struct {
	Original string   // Original target string (hostname, IP, CIDR)
	IPs      []net.IP // Resolved IP addresses
	Hostname string   // Resolved hostname (if applicable)
}

// AuthService represents a service that supports authentication for brute force attacks
type AuthService struct {
	Host        string      // Target host
	Port        int         // Service port
	Service     string      // Service name (ssh, ftp, http, etc.)
	Protocol    string      // Protocol (TCP/UDP)
	Banner      string      // Service banner
	ServiceInfo ServiceInfo // Detailed service information
}

// DDoSTarget represents a target suitable for DDoS testing
type DDoSTarget struct {
	URL         string      // Full URL for the target
	Host        string      // Target host
	Port        int         // Service port
	Scheme      string      // HTTP or HTTPS
	ServiceInfo ServiceInfo // Detailed service information
}
