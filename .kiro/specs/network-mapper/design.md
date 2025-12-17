# Network Mapper Design Document

## Overview

The Network Mapper module provides comprehensive network discovery and port scanning capabilities similar to NMAP, integrated seamlessly into the Letgo security testing framework. The module enables security testers to perform network reconnaissance, port scanning, service detection, and OS fingerprinting with a user-friendly console interface.

The design follows the existing Letgo architecture patterns, utilizing Go's concurrency features for high-performance scanning while maintaining compatibility with the current console menu system and data storage conventions.

## Architecture

The Network Mapper follows a modular architecture with clear separation of concerns:

```
Network Mapper Module
├── Scanner Engine (Core scanning logic)
├── Port Scanner (TCP/UDP port scanning)
├── Service Detector (Service identification and banner grabbing)
├── OS Fingerprinter (Operating system detection)
├── IP Resolver (Hostname to IP resolution and analysis)
├── Protection Detector (CDN/WAF/Security service detection)
├── Infrastructure Analyzer (Hosting provider and geolocation analysis)
├── Result Manager (Output formatting and storage)
├── Profile Manager (Scan profile management)
├── Progress Monitor (Real-time progress tracking)
└── Console Interface (Menu integration)
```

### Key Design Principles

1. **Concurrency**: Leverage Go's goroutines for parallel scanning across multiple hosts and ports
2. **Modularity**: Each component has a single responsibility and clear interfaces
3. **Extensibility**: Easy to add new scan types, output formats, and detection techniques
4. **Integration**: Seamless integration with existing Letgo modules and data structures
5. **Performance**: Optimized for speed while respecting network resources and avoiding detection

## Components and Interfaces

### Scanner Engine

The core scanning engine coordinates all scanning activities and manages the overall scan lifecycle.

```go
type ScannerEngine interface {
    Scan(ctx context.Context, config ScanConfig) (*ScanResult, error)
    Pause() error
    Resume() error
    Stop() error
    GetProgress() ProgressInfo
}

type ScanConfig struct {
    Targets            []string          // IP addresses, hostnames, or CIDR ranges
    Ports              []int             // Specific ports to scan
    PortRanges         []PortRange       // Port ranges to scan
    ScanType           ScanType          // TCP SYN, TCP Connect, UDP, etc.
    ScanProfile        ScanProfile       // Quick, comprehensive, stealth, vulnerability
    ServiceDetect      bool              // Enable service detection
    OSDetect           bool              // Enable OS fingerprinting
    ProtectionDetect   bool              // Enable CDN/WAF detection
    InfraAnalysis      bool              // Enable infrastructure analysis
    SubdomainEnum      bool              // Enable subdomain enumeration
    IncludeIPv6        bool              // Include IPv6 addresses in resolution
    MaxThreads         int               // Concurrent scanning threads
    Timeout            time.Duration     // Per-port timeout
    DNSTimeout         time.Duration     // DNS resolution timeout
    OutputFormat       OutputFormat      // JSON, XML, text
    OutputFile         string            // Output file path
    OnProgress         ProgressCallback  // Progress update callback
}
```

### Port Scanner

Handles the actual port scanning using different techniques (TCP SYN, TCP Connect, UDP).

```go
type PortScanner interface {
    ScanPort(ctx context.Context, target string, port int, scanType ScanType) PortResult
    ScanPorts(ctx context.Context, target string, ports []int, scanType ScanType) []PortResult
}

type PortResult struct {
    Port       int
    Protocol   string        // TCP or UDP
    State      PortState     // Open, Closed, Filtered
    Service    ServiceInfo   // Detected service information
    Banner     string        // Service banner if available
    ResponseTime time.Duration
}

type PortState int
const (
    PortOpen PortState = iota
    PortClosed
    PortFiltered
)
```

### Service Detector

Identifies services running on open ports through banner grabbing and service-specific probes.

```go
type ServiceDetector interface {
    DetectService(ctx context.Context, target string, port int) ServiceInfo
    GrabBanner(ctx context.Context, target string, port int) (string, error)
}

type ServiceInfo struct {
    Name        string            // Service name (e.g., "http", "ssh", "mysql")
    Version     string            // Service version
    Product     string            // Product name
    ExtraInfo   map[string]string // Additional service details
    Confidence  float64           // Detection confidence (0-100)
}
```

### OS Fingerprinter

Performs operating system detection using TCP/IP stack analysis and other fingerprinting techniques.

```go
type OSFingerprinter interface {
    DetectOS(ctx context.Context, target string, openPorts []int) OSInfo
}

type OSInfo struct {
    Family      string    // OS family (Linux, Windows, etc.)
    Version     string    // OS version
    Matches     []OSMatch // All possible matches
    Confidence  float64   // Overall confidence
}

type OSMatch struct {
    Name       string  // OS name
    Version    string  // OS version
    Confidence float64 // Match confidence
}
```

### IP Resolver

Handles hostname resolution, reverse DNS lookups, and IP address analysis.

```go
type IPResolver interface {
    ResolveHostname(hostname string) ([]ResolvedIP, error)
    ReverseLookup(ip string) ([]string, error)
    GetIPInfo(ip string) (IPInfo, error)
}

type ResolvedIP struct {
    IP       string    // IP address
    Type     string    // IPv4 or IPv6
    TTL      int       // DNS TTL
    Source   string    // DNS server used
}

type IPInfo struct {
    IP           string            // IP address
    ASN          string            // Autonomous System Number
    Organization string            // Organization/ISP name
    Country      string            // Country code
    Region       string            // Region/state
    City         string            // City
    Timezone     string            // Timezone
    ISP          string            // Internet Service Provider
    Metadata     map[string]string // Additional information
}
```

### Protection Detector

Identifies CDN, WAF, and other protection services in front of target hosts.

```go
type ProtectionDetector interface {
    DetectProtection(ctx context.Context, target string, port int) ([]ProtectionService, error)
    AnalyzeHTTPHeaders(headers map[string]string) ([]ProtectionService, error)
    DetectCDN(ctx context.Context, hostname string) (CDNInfo, error)
    DetectWAF(ctx context.Context, target string, port int) (WAFInfo, error)
}

type ProtectionService struct {
    Type        ProtectionType    // CDN, WAF, DDoS Protection, etc.
    Name        string            // Service name (Cloudflare, Fastly, etc.)
    Confidence  float64           // Detection confidence (0-100)
    Evidence    []string          // Evidence used for detection
    Details     map[string]string // Additional service details
}

type ProtectionType int
const (
    ProtectionCDN ProtectionType = iota
    ProtectionWAF
    ProtectionDDoS
    ProtectionLoadBalancer
    ProtectionProxy
    ProtectionFirewall
)

type CDNInfo struct {
    Provider    string   // CDN provider name
    EdgeServers []string // Edge server locations
    Features    []string // Detected CDN features
}

type WAFInfo struct {
    Vendor      string   // WAF vendor
    Product     string   // WAF product name
    Version     string   // WAF version if detectable
    Rules       []string // Detected rule signatures
}
```

### Infrastructure Analyzer

Analyzes hosting infrastructure, SSL certificates, and related infrastructure details.

```go
type InfrastructureAnalyzer interface {
    AnalyzeInfrastructure(ctx context.Context, target string) (InfrastructureInfo, error)
    GetSSLCertificate(ctx context.Context, hostname string, port int) (SSLCertInfo, error)
    EnumerateSubdomains(ctx context.Context, domain string) ([]string, error)
}

type InfrastructureInfo struct {
    HostingProvider string            // Hosting provider name
    CloudPlatform   string            // Cloud platform (AWS, GCP, Azure, etc.)
    DataCenter      string            // Data center location
    NetworkInfo     NetworkInfo       // Network-related information
    SSLInfo         SSLCertInfo       // SSL certificate information
    Subdomains      []string          // Discovered subdomains
    RelatedDomains  []string          // Related domain names
}

type NetworkInfo struct {
    ASN          string // Autonomous System Number
    BGPPrefix    string // BGP prefix
    Organization string // Network organization
    Abuse        string // Abuse contact
}

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
```

### Result Manager

Handles formatting, storage, and export of scan results in multiple formats.

```go
type ResultManager interface {
    SaveResults(results *ScanResult, format OutputFormat, filename string) error
    ExportResults(results *ScanResult, format OutputFormat) ([]byte, error)
    LoadResults(filename string) (*ScanResult, error)
}

type ScanResult struct {
    Timestamp    time.Time
    ScanConfig   ScanConfig
    Hosts        []HostResult
    Statistics   ScanStatistics
}

type HostResult struct {
    Target          string              // Original target (hostname or IP)
    ResolvedIPs     []ResolvedIP        // All resolved IP addresses
    Status          HostStatus          // Up, Down, Unknown
    Ports           []PortResult        // Port scan results
    OS              OSInfo              // Operating system information
    Protection      []ProtectionService // Detected protection services
    Infrastructure  InfrastructureInfo  // Infrastructure analysis
    ResponseTime    time.Duration       // Response time
}

type HostStatus int
const (
    HostUp HostStatus = iota
    HostDown
    HostUnknown
    HostFiltered
)
```

## Data Models

### Core Data Structures

The Network Mapper uses structured data models to represent scan configurations, results, and metadata:

```go
// Scan configuration profiles
type ScanProfile struct {
    Name        string
    Description string
    Ports       []int
    ScanType    ScanType
    Timing      TimingProfile
    Options     ScanOptions
}

// Timing profiles for stealth and performance tuning
type TimingProfile struct {
    ConnectTimeout   time.Duration
    ReadTimeout      time.Duration
    DelayBetweenPorts time.Duration
    MaxRetries       int
}

// Scan options and flags
type ScanOptions struct {
    ServiceDetection   bool
    OSDetection       bool
    ProtectionDetect  bool
    InfraAnalysis     bool
    SubdomainEnum     bool
    AggressiveMode    bool
    StealthMode       bool
    FragmentPackets   bool
    IncludeIPv6       bool
}

// Progress tracking information
type ProgressInfo struct {
    HostsScanned    int
    HostsTotal      int
    PortsScanned    int
    PortsTotal      int
    ElapsedTime     time.Duration
    EstimatedTime   time.Duration
    ScanRate        float64  // Ports per second
}
```

### Port and Service Definitions

The module includes comprehensive port and service definitions:

```go
// Common port definitions
var CommonPorts = map[int]string{
    21:   "ftp",
    22:   "ssh",
    23:   "telnet",
    25:   "smtp",
    53:   "dns",
    80:   "http",
    110:  "pop3",
    143:  "imap",
    443:  "https",
    993:  "imaps",
    995:  "pop3s",
    // ... top 1000 ports
}

// Service detection signatures
type ServiceSignature struct {
    Port        int
    Protocol    string
    Probe       []byte
    Match       *regexp.Regexp
    ServiceName string
    Version     *regexp.Regexp
}
```

### Protection Detection Databases

The module includes comprehensive databases for identifying protection services:

```go
// CDN provider signatures
var CDNSignatures = map[string]CDNSignature{
    "cloudflare": {
        Name: "Cloudflare",
        Headers: []string{"cf-ray", "cf-cache-status", "server: cloudflare"},
        IPRanges: []string{"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22"},
        ASNs: []string{"AS13335"},
        CNAMEPatterns: []string{".cloudflare.com", ".cloudflare.net"},
    },
    "fastly": {
        Name: "Fastly",
        Headers: []string{"fastly-debug-digest", "x-served-by", "x-cache"},
        IPRanges: []string{"23.235.32.0/20", "43.249.72.0/22"},
        ASNs: []string{"AS54113"},
        CNAMEPatterns: []string{".fastly.com", ".fastlylb.net"},
    },
    "cloudfront": {
        Name: "Amazon CloudFront",
        Headers: []string{"x-amz-cf-id", "x-amz-cf-pop", "via: cloudfront"},
        IPRanges: []string{"13.32.0.0/15", "13.35.0.0/17"},
        ASNs: []string{"AS16509"},
        CNAMEPatterns: []string{".cloudfront.net"},
    },
    // Additional CDN providers: Akamai, KeyCDN, MaxCDN, etc.
}

type CDNSignature struct {
    Name          string
    Headers       []string
    IPRanges      []string
    ASNs          []string
    CNAMEPatterns []string
    Confidence    float64
}

// WAF detection signatures
var WAFSignatures = map[string]WAFSignature{
    "cloudflare_waf": {
        Name: "Cloudflare WAF",
        Headers: []string{"cf-ray", "server: cloudflare"},
        BlockPages: []string{"Attention Required! | Cloudflare", "Ray ID:"},
        ErrorCodes: []int{403, 429, 503},
        Fingerprints: []string{"cloudflare", "cf-ray"},
        TestPayloads: []string{"<script>alert(1)</script>", "' OR 1=1--", "../../../etc/passwd"},
    },
    "aws_waf": {
        Name: "AWS WAF",
        Headers: []string{"x-amzn-requestid", "x-amzn-errortype"},
        BlockPages: []string{"AWS WAF", "Request blocked"},
        ErrorCodes: []int{403},
        Fingerprints: []string{"aws", "amazon"},
        TestPayloads: []string{"<script>", "union select", "cmd="},
    },
    // Additional WAF signatures: ModSecurity, F5, Imperva, etc.
}

type WAFSignature struct {
    Name         string
    Headers      []string
    BlockPages   []string
    ErrorCodes   []int
    Fingerprints []string
    TestPayloads []string
}

// Hosting provider identification
var HostingProviders = map[string]HostingProvider{
    "aws": {
        Name: "Amazon Web Services",
        ASNs: []string{"AS16509", "AS14618"},
        IPRanges: []string{"3.0.0.0/8", "13.0.0.0/8", "18.0.0.0/8"},
        Domains: []string{".amazonaws.com", ".aws.amazon.com"},
        Features: []string{"ec2", "s3", "cloudfront", "elb"},
    },
    "gcp": {
        Name: "Google Cloud Platform",
        ASNs: []string{"AS15169", "AS36040"},
        IPRanges: []string{"34.64.0.0/10", "35.184.0.0/13"},
        Domains: []string{".googleusercontent.com", ".googleapis.com"},
        Features: []string{"gce", "gcs", "gae"},
    },
    "azure": {
        Name: "Microsoft Azure",
        ASNs: []string{"AS8075"},
        IPRanges: []string{"13.64.0.0/11", "20.0.0.0/8"},
        Domains: []string{".azurewebsites.net", ".azure.com"},
        Features: []string{"vm", "storage", "cdn"},
    },
    // Additional hosting providers: DigitalOcean, Linode, Vultr, etc.
}

type HostingProvider struct {
    Name     string
    ASNs     []string
    IPRanges []string
    Domains  []string
    Features []string
}
```

### Detection Algorithms

The protection detection system uses multiple techniques for accurate identification:

```go
// Multi-layered detection approach
type DetectionEngine struct {
    cdnDB     map[string]CDNSignature
    wafDB     map[string]WAFSignature
    hostingDB map[string]HostingProvider
    geoIP     GeoIPDatabase
    asnDB     ASNDatabase
}

// Detection methods with confidence scoring
func (de *DetectionEngine) DetectCDN(ctx context.Context, target string) ([]ProtectionService, error) {
    var services []ProtectionService

    // 1. HTTP Header Analysis (40% weight)
    headers := de.getHTTPHeaders(ctx, target)
    cdnFromHeaders := de.analyzeCDNHeaders(headers)

    // 2. IP Range Analysis (30% weight)
    ips := de.resolveIPs(target)
    cdnFromIPs := de.analyzeCDNIPs(ips)

    // 3. CNAME Analysis (20% weight)
    cnames := de.getCNAMERecords(target)
    cdnFromCNAME := de.analyzeCDNCNAME(cnames)

    // 4. ASN Analysis (10% weight)
    cdnFromASN := de.analyzeCDNASN(ips)

    // Combine results with weighted confidence scoring
    return de.combineDetectionResults(cdnFromHeaders, cdnFromIPs, cdnFromCNAME, cdnFromASN), nil
}

func (de *DetectionEngine) DetectWAF(ctx context.Context, target string, port int) ([]ProtectionService, error) {
    var services []ProtectionService

    // 1. Passive Detection - HTTP Headers (50% weight)
    headers := de.getHTTPHeaders(ctx, target)
    wafFromHeaders := de.analyzeWAFHeaders(headers)

    // 2. Active Detection - Test Payloads (30% weight)
    wafFromPayloads := de.testWAFPayloads(ctx, target, port)

    // 3. Error Page Analysis (20% weight)
    wafFromErrors := de.analyzeErrorPages(ctx, target, port)

    return de.combineWAFResults(wafFromHeaders, wafFromPayloads, wafFromErrors), nil
}
```

## Correctness Properties

_A property is a characteristic or behavior that should hold true across all valid executions of a system-essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees._

Based on the prework analysis, the following correctness properties ensure the Network Mapper functions correctly across all valid inputs and scenarios:

### Property 1: Target Scanning Completeness

_For any_ valid IP address or hostname provided as a target, the Network_Mapper should attempt to scan the specified target and return scan results
**Validates: Requirements 1.1**

### Property 2: Port Range Compliance

_For any_ specified port range, the Network_Mapper should scan only ports within that range and no ports outside the range
**Validates: Requirements 1.2**

### Property 3: Scan Result Completeness

_For any_ completed port scan, the output should contain port number, state (open/closed/filtered), and protocol information for each scanned port
**Validates: Requirements 1.3**

### Property 4: CIDR Range Expansion

_For any_ valid CIDR notation target range, the Network_Mapper should scan all hosts within that range
**Validates: Requirements 2.1**

### Property 5: Connection Limiting

_For any_ concurrent scanning operation, the number of simultaneous connections should never exceed the specified maximum limit
**Validates: Requirements 2.3**

### Property 6: Progress Reporting

_For any_ scanning operation, real-time progress updates should be provided including completion percentage and estimated time remaining
**Validates: Requirements 2.4, 8.1, 8.2**

### Property 7: Error Resilience

_For any_ network error encountered during scanning, the error should be logged and scanning should continue with remaining targets
**Validates: Requirements 1.5, 2.5**

### Property 8: Service Detection Activation

_For any_ open port discovered, service identification should be attempted when service detection is enabled
**Validates: Requirements 3.1, 3.2**

### Property 9: Service Information Completeness

_For any_ successfully identified service, the output should include service name, version, and additional details
**Validates: Requirements 3.3**

### Property 10: OS Detection Execution

_For any_ target host when OS detection is enabled, network response analysis should be performed to determine the operating system
**Validates: Requirements 4.1**

### Property 11: OS Information Completeness

_For any_ completed OS fingerprinting, the output should include OS family, version, and confidence level
**Validates: Requirements 4.2**

### Property 12: Scan Type Implementation

_For any_ selected scan type (TCP SYN, TCP Connect, UDP), the appropriate scanning technique should be used
**Validates: Requirements 5.1, 5.2, 5.3**

### Property 13: Stealth Mode Behavior

_For any_ scan with stealth mode enabled, timing delays and packet fragmentation should be used to avoid detection
**Validates: Requirements 5.4**

### Property 14: Result Persistence

_For any_ completed scan, results should be saved to a structured file format with timestamp, scan parameters, and detailed findings
**Validates: Requirements 6.1, 6.3**

### Property 15: Export Format Support

_For any_ result export operation, the system should support JSON, XML, and plain text output formats
**Validates: Requirements 6.2**

### Property 16: Result Organization

_For any_ exported results, data should be organized by host with nested port and service information
**Validates: Requirements 6.4**

### Property 17: Profile Configuration Persistence

_For any_ custom scan profile created, the configuration should be saveable and reusable in future scans
**Validates: Requirements 7.5**

### Property 18: Scan Control Operations

_For any_ running scan, pause, resume, and stop operations should function correctly with appropriate state management
**Validates: Requirements 8.3, 8.4**

### Property 19: Integration Compatibility

_For any_ discovered web service, export options should be provided for integration with other Letgo modules
**Validates: Requirements 9.2, 9.3**

### Property 20: File System Consistency

_For any_ Network_Mapper file operation, the same data directory structure should be used as other Letgo modules
**Validates: Requirements 9.4, 9.5**

### Property 21: Hostname IP Resolution

_For any_ hostname provided as a target, all associated IP addresses should be resolved and displayed in the scan results
**Validates: Requirements 10.1**

### Property 22: Multiple IP Scanning Completeness

_For any_ hostname that resolves to multiple IP addresses, all resolved IPs should be included in the scanning process
**Validates: Requirements 10.2**

### Property 23: Hostname and IP Display Completeness

_For any_ scan result involving a hostname, both the original hostname and all resolved IP addresses should be shown in the output
**Validates: Requirements 10.3**

### Property 24: DNS Resolution Error Resilience

_For any_ DNS resolution failure, the error should be logged and scanning should continue with remaining targets
**Validates: Requirements 10.4**

### Property 25: IPv6 Address Inclusion

_For any_ hostname that resolves to IPv6 addresses, they should be included in results alongside IPv4 addresses
**Validates: Requirements 10.5**

### Property 26: CDN Detection Activation

_For any_ web service scanned, CDN detection should be attempted to identify services like Cloudflare, Fastly, and CloudFront
**Validates: Requirements 11.1**

### Property 27: Protection Service Information Completeness

_For any_ detected protection service, the output should include service name, type, and confidence level
**Validates: Requirements 11.2**

### Property 28: WAF Signature Analysis

_For any_ HTTP headers analyzed, WAF signatures and security headers should be identified when present
**Validates: Requirements 11.3**

### Property 29: Multiple Protection Layer Detection

_For any_ target with multiple protection layers, all identified services should be listed in the results
**Validates: Requirements 11.4**

### Property 30: Protection Status Indication

_For any_ protection detection that is inconclusive, the protection status should be indicated as unknown rather than omitted
**Validates: Requirements 11.5**

### Property 31: Reverse DNS Lookup Execution

_For any_ hostname analysis, reverse DNS lookups should be performed on all resolved IP addresses
**Validates: Requirements 12.1**

### Property 32: Hosting Provider Identification

_For any_ identified IP address, hosting provider or ASN information should be determined and included
**Validates: Requirements 12.2**

### Property 33: Geolocation Information Inclusion

_For any_ IP address where geolocation data is available, country and region information should be included
**Validates: Requirements 12.3**

### Property 34: SSL Certificate Analysis

_For any_ SSL-enabled service, certificate details including issuer and subject alternative names should be extracted
**Validates: Requirements 12.4**

### Property 35: Subdomain Discovery Execution

_For any_ domain when subdomain enumeration is enabled, related subdomain discovery should be attempted
**Validates: Requirements 12.5**

## Error Handling

The Network Mapper implements comprehensive error handling to ensure robust operation:

### Network Error Handling

- Connection timeouts: Retry with exponential backoff
- Host unreachable: Mark host as down and continue
- Port filtering: Detect and report filtered ports
- DNS resolution failures: Log error and continue with other targets
- IPv6 resolution failures: Fall back to IPv4 only
- Protection detection timeouts: Mark protection status as unknown
- SSL certificate errors: Log error but continue with basic analysis
- Subdomain enumeration failures: Continue with main domain analysis

### Resource Management

- Memory usage monitoring for large scans
- File descriptor limits for concurrent connections
- Graceful degradation when system limits are reached
- Cleanup of resources on scan termination

### Input Validation

- IP address and hostname validation (IPv4 and IPv6)
- Port range validation (1-65535)
- CIDR notation parsing and validation
- Domain name format validation
- SSL certificate chain validation
- Configuration parameter bounds checking
- Protection detection payload sanitization

### Recovery Mechanisms

- Partial result saving on interruption
- Scan state persistence for resume capability
- Automatic retry for transient failures
- Fallback to alternative scan methods when needed

## Testing Strategy

The Network Mapper employs a dual testing approach combining unit tests and property-based tests to ensure comprehensive coverage and correctness.

### Unit Testing Requirements

Unit tests verify specific examples, edge cases, and integration points:

- **Configuration Parsing**: Test scan profile loading and validation
- **Target Resolution**: Test IP address, hostname, and CIDR parsing
- **Port Scanning**: Test individual scan techniques (SYN, Connect, UDP)
- **Service Detection**: Test service identification with known signatures
- **OS Fingerprinting**: Test OS detection with known fingerprints
- **Result Formatting**: Test output generation in all supported formats
- **Error Conditions**: Test handling of network errors and invalid inputs
- **Integration Points**: Test console menu integration and file operations

### Property-Based Testing Requirements

Property-based tests verify universal properties using **testify/quick** for Go, configured to run a minimum of 100 iterations per property. Each property-based test will be tagged with a comment explicitly referencing the correctness property from this design document using the format: **Feature: network-mapper, Property {number}: {property_text}**

Key property tests include:

- **Scan Completeness**: Generate random valid targets and verify all are scanned
- **Port Range Compliance**: Generate random port ranges and verify scanning boundaries
- **Concurrency Limits**: Generate random thread counts and verify connection limits
- **Result Consistency**: Generate random scan configurations and verify output format
- **Error Resilience**: Inject random network errors and verify continued operation
- **State Management**: Generate random pause/resume sequences and verify scan state
- **Format Compatibility**: Generate random results and verify all export formats work
- **IP Resolution**: Generate random hostnames and verify all resolved IPs are included
- **Protection Detection**: Generate random web services and verify protection analysis
- **Infrastructure Analysis**: Generate random targets and verify hosting/certificate info

### Integration Testing

- **Console Menu Integration**: Verify menu options and user interaction flows
- **File System Integration**: Test result storage and configuration file handling
- **Module Interoperability**: Test integration with other Letgo modules
- **Performance Testing**: Verify scanning performance under various loads
- **Network Compatibility**: Test against different network configurations and firewalls

The testing strategy ensures that both specific functionality works correctly (unit tests) and that general correctness properties hold across all inputs (property-based tests), providing comprehensive validation of the Network Mapper's behavior.
