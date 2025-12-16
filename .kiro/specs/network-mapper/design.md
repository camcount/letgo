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
    Targets        []string          // IP addresses, hostnames, or CIDR ranges
    Ports          []int             // Specific ports to scan
    PortRanges     []PortRange       // Port ranges to scan
    ScanType       ScanType          // TCP SYN, TCP Connect, UDP, etc.
    ScanProfile    ScanProfile       // Quick, comprehensive, stealth, vulnerability
    ServiceDetect  bool              // Enable service detection
    OSDetect       bool              // Enable OS fingerprinting
    MaxThreads     int               // Concurrent scanning threads
    Timeout        time.Duration     // Per-port timeout
    OutputFormat   OutputFormat      // JSON, XML, text
    OutputFile     string            // Output file path
    OnProgress     ProgressCallback  // Progress update callback
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
    Target      string
    Status      HostStatus  // Up, Down, Unknown
    Ports       []PortResult
    OS          OSInfo
    ResponseTime time.Duration
}
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
    ServiceDetection bool
    OSDetection     bool
    AggressiveMode  bool
    StealthMode     bool
    FragmentPackets bool
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

## Error Handling

The Network Mapper implements comprehensive error handling to ensure robust operation:

### Network Error Handling

- Connection timeouts: Retry with exponential backoff
- Host unreachable: Mark host as down and continue
- Port filtering: Detect and report filtered ports
- DNS resolution failures: Log error and skip invalid targets

### Resource Management

- Memory usage monitoring for large scans
- File descriptor limits for concurrent connections
- Graceful degradation when system limits are reached
- Cleanup of resources on scan termination

### Input Validation

- IP address and hostname validation
- Port range validation (1-65535)
- CIDR notation parsing and validation
- Configuration parameter bounds checking

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

### Integration Testing

- **Console Menu Integration**: Verify menu options and user interaction flows
- **File System Integration**: Test result storage and configuration file handling
- **Module Interoperability**: Test integration with other Letgo modules
- **Performance Testing**: Verify scanning performance under various loads
- **Network Compatibility**: Test against different network configurations and firewalls

The testing strategy ensures that both specific functionality works correctly (unit tests) and that general correctness properties hold across all inputs (property-based tests), providing comprehensive validation of the Network Mapper's behavior.
