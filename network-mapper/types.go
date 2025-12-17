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
	Targets          []string         `json:"targets" xml:"targets"`                       // IP addresses, hostnames, or CIDR ranges
	Ports            []int            `json:"ports" xml:"ports"`                           // Specific ports to scan
	PortRanges       []PortRange      `json:"port_ranges" xml:"port_ranges"`               // Port ranges to scan
	ScanType         ScanType         `json:"scan_type" xml:"scan_type"`                   // TCP SYN, TCP Connect, UDP, etc.
	ScanProfile      ScanProfile      `json:"scan_profile" xml:"scan_profile"`             // Quick, comprehensive, stealth, vulnerability
	ServiceDetect    bool             `json:"service_detect" xml:"service_detect"`         // Enable service detection
	OSDetect         bool             `json:"os_detect" xml:"os_detect"`                   // Enable OS fingerprinting
	ProtectionDetect bool             `json:"protection_detect" xml:"protection_detect"`   // Enable CDN/WAF detection
	InfraAnalysis    bool             `json:"infra_analysis" xml:"infra_analysis"`         // Enable infrastructure analysis
	SubdomainEnum    bool             `json:"subdomain_enum" xml:"subdomain_enum"`         // Enable subdomain enumeration
	IncludeIPv6      bool             `json:"include_ipv6" xml:"include_ipv6"`             // Include IPv6 addresses in resolution
	MaxThreads       int              `json:"max_threads" xml:"max_threads"`               // Concurrent scanning threads
	Timeout          time.Duration    `json:"timeout" xml:"timeout"`                       // Per-port timeout
	DNSTimeout       time.Duration    `json:"dns_timeout" xml:"dns_timeout"`               // DNS resolution timeout
	OutputFormat     OutputFormat     `json:"output_format" xml:"output_format"`           // JSON, XML, text
	OutputFile       string           `json:"output_file" xml:"output_file"`               // Output file path
	OnProgress       ProgressCallback `json:"-" xml:"-"`                                   // Progress update callback (not serialized)
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
	Target          string              `json:"target" xml:"target"`                         // Original target (hostname or IP)
	ResolvedIPs     []ResolvedIP        `json:"resolved_ips" xml:"resolved_ips"`             // All resolved IP addresses
	Status          HostStatus          `json:"status" xml:"status"`                         // Up, Down, Unknown
	Ports           []PortResult        `json:"ports" xml:"ports"`                           // Scan results for each port
	OS              OSInfo              `json:"os" xml:"os"`                                 // OS detection results
	Protection      []ProtectionService `json:"protection" xml:"protection"`                 // Detected protection services
	Infrastructure  InfrastructureInfo  `json:"infrastructure" xml:"infrastructure"`         // Infrastructure analysis
	ResponseTime    time.Duration       `json:"response_time" xml:"response_time"`           // Host response time
}

// ResolvedIP represents a resolved IP address with metadata
type ResolvedIP struct {
	IP         string    `json:"ip" xml:"ip"`                   // IP address
	Type       string    `json:"type" xml:"type"`               // IPv4 or IPv6
	TTL        int       `json:"ttl" xml:"ttl"`                 // DNS TTL (if available)
	Source     string    `json:"source" xml:"source"`           // DNS server used (if available)
	Hostname   string    `json:"hostname" xml:"hostname"`       // Original hostname
	ResolvedAt time.Time `json:"resolved_at" xml:"resolved_at"` // When the resolution occurred
}

// IPInfo contains comprehensive information about an IP address
type IPInfo struct {
	IP              string            // IP address
	ASN             string            // Autonomous System Number
	Organization    string            // Organization/ISP name
	Country         string            // Country code
	Region          string            // Region/state
	City            string            // City
	Timezone        string            // Timezone
	ISP             string            // Internet Service Provider
	HostingProvider string            // Hosting provider name
	CloudPlatform   string            // Cloud platform (AWS, GCP, Azure, etc.)
	Metadata        map[string]string // Additional information
}

// ProtectionService represents a detected protection service
type ProtectionService struct {
	Type        ProtectionType    `json:"type" xml:"type"`               // CDN, WAF, DDoS Protection, etc.
	Name        string            `json:"name" xml:"name"`               // Service name (Cloudflare, Fastly, etc.)
	Confidence  float64           `json:"confidence" xml:"confidence"`   // Detection confidence (0-100)
	Evidence    []string          `json:"evidence" xml:"evidence"`       // Evidence used for detection
	Details     []KeyValue        `json:"details" xml:"details"`         // Additional service details
}

// ProtectionType represents different types of protection services
type ProtectionType int

const (
	ProtectionCDN ProtectionType = iota
	ProtectionWAF
	ProtectionDDoS
	ProtectionLoadBalancer
	ProtectionProxy
	ProtectionFirewall
)

// String returns the string representation of ProtectionType
func (pt ProtectionType) String() string {
	switch pt {
	case ProtectionCDN:
		return "CDN"
	case ProtectionWAF:
		return "WAF"
	case ProtectionDDoS:
		return "DDoS Protection"
	case ProtectionLoadBalancer:
		return "Load Balancer"
	case ProtectionProxy:
		return "Proxy"
	case ProtectionFirewall:
		return "Firewall"
	default:
		return "Unknown"
	}
}

// InfrastructureInfo contains infrastructure analysis results
type InfrastructureInfo struct {
	HostingProvider string            `json:"hosting_provider" xml:"hosting_provider"` // Hosting provider name
	CloudPlatform   string            `json:"cloud_platform" xml:"cloud_platform"`     // Cloud platform (AWS, GCP, Azure, etc.)
	DataCenter      string            `json:"data_center" xml:"data_center"`           // Data center location
	NetworkInfo     NetworkInfo       `json:"network_info" xml:"network_info"`         // Network-related information
	SSLInfo         SSLCertInfo       `json:"ssl_info" xml:"ssl_info"`                 // SSL certificate information
	Subdomains      []string          `json:"subdomains" xml:"subdomains"`             // Discovered subdomains
	RelatedDomains  []string          `json:"related_domains" xml:"related_domains"`   // Related domain names
}

// NetworkInfo contains network-related information
type NetworkInfo struct {
	ASN          string `json:"asn" xml:"asn"`                   // Autonomous System Number
	BGPPrefix    string `json:"bgp_prefix" xml:"bgp_prefix"`     // BGP prefix
	Organization string `json:"organization" xml:"organization"` // Network organization
	Abuse        string `json:"abuse" xml:"abuse"`               // Abuse contact
}

// SSLCertInfo contains SSL certificate information
type SSLCertInfo struct {
	Issuer          string    // Certificate issuer
	Subject         string    // Certificate subject
	SANs            []string  // Subject Alternative Names
	ValidFrom       time.Time // Certificate valid from
	ValidTo         time.Time // Certificate valid to
	Fingerprint     string    // Certificate fingerprint
	SignatureAlg    string    // Signature algorithm
	KeySize         int       // Key size in bits
	IsWildcard      bool      // Is wildcard certificate
	IsSelfSigned    bool      // Is self-signed certificate
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

// ResolveOptions contains options for hostname resolution
type ResolveOptions struct {
	IncludeIPv4 bool          // Include IPv4 addresses
	IncludeIPv6 bool          // Include IPv6 addresses
	Timeout     time.Duration // DNS resolution timeout
	Retries     int           // Number of retry attempts
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
