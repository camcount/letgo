package networkmapper

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ValidationError represents a validation error
type ValidationError struct {
	Field   string
	Value   interface{}
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s' with value '%v': %s", e.Field, e.Value, e.Message)
}

// ValidatePortRange validates that all ports in a range are within valid bounds (1-65535)
// Requirements 1.5, 2.5
func ValidatePortRange(ports []int) error {
	for _, port := range ports {
		if !isValidPort(port) {
			return ValidationError{
				Field:   "port",
				Value:   port,
				Message: "port must be between 1 and 65535",
			}
		}
	}
	return nil
}

// ValidatePortRanges validates that all port ranges are valid
func ValidatePortRanges(ranges []PortRange) error {
	for i, portRange := range ranges {
		if portRange.Start < 1 || portRange.Start > 65535 {
			return ValidationError{
				Field:   fmt.Sprintf("port_ranges[%d].start", i),
				Value:   portRange.Start,
				Message: "start port must be between 1 and 65535",
			}
		}
		if portRange.End < 1 || portRange.End > 65535 {
			return ValidationError{
				Field:   fmt.Sprintf("port_ranges[%d].end", i),
				Value:   portRange.End,
				Message: "end port must be between 1 and 65535",
			}
		}
		if portRange.Start > portRange.End {
			return ValidationError{
				Field:   fmt.Sprintf("port_ranges[%d]", i),
				Value:   portRange,
				Message: "start port must be less than or equal to end port",
			}
		}
	}
	return nil
}

// ValidateTargets validates that all targets are valid IP addresses, hostnames, CIDR ranges, or IP ranges
func ValidateTargets(targets []string) error {
	for i, target := range targets {
		if target == "" {
			return ValidationError{
				Field:   fmt.Sprintf("targets[%d]", i),
				Value:   target,
				Message: "target cannot be empty",
			}
		}

		target = strings.TrimSpace(target)

		// Check if it's a valid IP address
		if ip := net.ParseIP(target); ip != nil {
			continue
		}

		// Check if it's a valid CIDR range
		if _, _, err := net.ParseCIDR(target); err == nil {
			// Additional CIDR validation for size limits
			if err := ValidateCIDRSize(target); err != nil {
				return ValidationError{
					Field:   fmt.Sprintf("targets[%d]", i),
					Value:   target,
					Message: err.Error(),
				}
			}
			continue
		}

		// Check if it's an IP range (e.g., 192.168.1.1-10 or 192.168.1.1-192.168.1.10)
		if strings.Contains(target, "-") {
			if err := ValidateIPRange(target); err != nil {
				return ValidationError{
					Field:   fmt.Sprintf("targets[%d]", i),
					Value:   target,
					Message: err.Error(),
				}
			}
			continue
		}

		// Check if it's a valid hostname
		if isValidHostname(target) {
			continue
		}

		return ValidationError{
			Field:   fmt.Sprintf("targets[%d]", i),
			Value:   target,
			Message: "target must be a valid IP address, hostname, CIDR range, or IP range",
		}
	}
	return nil
}

// ValidateIPRange validates an IP range specification
func ValidateIPRange(target string) error {
	parts := strings.Split(target, "-")
	if len(parts) != 2 {
		return fmt.Errorf("invalid IP range format: %s", target)
	}

	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	if startIP == nil {
		return fmt.Errorf("invalid start IP in range: %s", parts[0])
	}

	endStr := strings.TrimSpace(parts[1])

	// Check if end is just a number (last octet)
	var endOctet int
	if _, err := fmt.Sscanf(endStr, "%d", &endOctet); err == nil {
		// Validate that it's a valid octet value
		if endOctet < 0 || endOctet > 255 {
			return fmt.Errorf("end octet out of range (0-255): %d", endOctet)
		}

		// Validate that start IP is IPv4 for octet notation
		if startIP.To4() == nil {
			return fmt.Errorf("octet notation only supported for IPv4 addresses")
		}

		// Validate that end octet is >= start octet
		startOctet := int(startIP.To4()[3])
		if endOctet < startOctet {
			return fmt.Errorf("end octet (%d) must be >= start octet (%d)", endOctet, startOctet)
		}

		return nil
	}

	// Check if end is a full IP address
	endIP := net.ParseIP(endStr)
	if endIP == nil {
		return fmt.Errorf("invalid end IP in range: %s", endStr)
	}

	// Validate that both IPs are the same type (IPv4 or IPv6)
	if (startIP.To4() == nil) != (endIP.To4() == nil) {
		return fmt.Errorf("start and end IPs must be the same type (both IPv4 or both IPv6)")
	}

	return nil
}

// ValidateCIDRSize validates that a CIDR range is not too large
func ValidateCIDRSize(cidr string) error {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR notation: %w", err)
	}

	// Check for reasonable CIDR size limits
	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones

	// Limit CIDR expansion to prevent memory issues
	const maxHostBits = 16 // 2^16 = 65536 addresses
	if hostBits > maxHostBits {
		if bits == 32 { // IPv4
			return fmt.Errorf("IPv4 CIDR range too large (max /%d)", 32-maxHostBits)
		} else { // IPv6
			return fmt.Errorf("IPv6 CIDR range too large (max /%d)", 128-maxHostBits)
		}
	}

	return nil
}

// ValidateScanConfig validates a complete scan configuration
func ValidateScanConfig(config ScanConfig) error {
	// Validate targets
	if len(config.Targets) == 0 {
		return ValidationError{
			Field:   "targets",
			Value:   config.Targets,
			Message: "at least one target must be specified",
		}
	}

	if err := ValidateTargets(config.Targets); err != nil {
		return err
	}

	// Validate ports
	if err := ValidatePortRange(config.Ports); err != nil {
		return err
	}

	// Validate port ranges
	if err := ValidatePortRanges(config.PortRanges); err != nil {
		return err
	}

	// Validate that we have either ports or port ranges
	if len(config.Ports) == 0 && len(config.PortRanges) == 0 {
		return ValidationError{
			Field:   "ports",
			Value:   nil,
			Message: "either specific ports or port ranges must be specified",
		}
	}

	// Validate max threads (0 means use default, so it's allowed)
	if config.MaxThreads < 0 {
		return ValidationError{
			Field:   "max_threads",
			Value:   config.MaxThreads,
			Message: "max threads cannot be negative (use 0 for default)",
		}
	}

	if config.MaxThreads > 1000 {
		return ValidationError{
			Field:   "max_threads",
			Value:   config.MaxThreads,
			Message: "max threads should not exceed 1000 to avoid resource exhaustion",
		}
	}

	// Validate timeout
	if config.Timeout <= 0 {
		return ValidationError{
			Field:   "timeout",
			Value:   config.Timeout,
			Message: "timeout must be greater than 0",
		}
	}

	// Validate scan type
	if config.ScanType < 0 || config.ScanType > 2 {
		return ValidationError{
			Field:   "scan_type",
			Value:   config.ScanType,
			Message: "scan type must be TCP SYN (0), TCP Connect (1), or UDP (2)",
		}
	}

	return nil
}

// isValidHostname checks if a string is a valid hostname
func isValidHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 253 {
		return false
	}

	// Hostname cannot start or end with a dot
	if strings.HasPrefix(hostname, ".") || strings.HasSuffix(hostname, ".") {
		return false
	}

	// Split into labels
	labels := strings.Split(hostname, ".")
	for _, label := range labels {
		if !isValidHostnameLabel(label) {
			return false
		}
	}

	return true
}

// isValidHostnameLabel checks if a hostname label is valid
func isValidHostnameLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 {
		return false
	}

	// Label cannot start or end with hyphen
	if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
		return false
	}

	// Check each character
	for _, char := range label {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '-') {
			return false
		}
	}

	return true
}

// ExpandPortRanges expands port ranges into individual port numbers
func ExpandPortRanges(ranges []PortRange) []int {
	var ports []int
	for _, portRange := range ranges {
		for port := portRange.Start; port <= portRange.End; port++ {
			ports = append(ports, port)
		}
	}
	return ports
}

// GetAllPorts combines explicit ports and expanded port ranges
func GetAllPorts(config ScanConfig) ([]int, error) {
	// Validate first
	if err := ValidatePortRange(config.Ports); err != nil {
		return nil, err
	}
	if err := ValidatePortRanges(config.PortRanges); err != nil {
		return nil, err
	}

	// Start with explicit ports
	allPorts := make([]int, len(config.Ports))
	copy(allPorts, config.Ports)

	// Add expanded ranges
	expandedPorts := ExpandPortRanges(config.PortRanges)
	allPorts = append(allPorts, expandedPorts...)

	// Remove duplicates
	portMap := make(map[int]bool)
	uniquePorts := []int{}

	for _, port := range allPorts {
		if !portMap[port] {
			portMap[port] = true
			uniquePorts = append(uniquePorts, port)
		}
	}

	return uniquePorts, nil
}

// IsNetworkError checks if an error is a network-related error that should be retried
func IsNetworkError(err error) bool {
	if err == nil {
		return false
	}

	// Check for network errors
	if netErr, ok := err.(net.Error); ok {
		return netErr.Temporary() || netErr.Timeout()
	}

	// Check for specific error types that indicate network issues
	errStr := err.Error()
	networkErrorStrings := []string{
		"connection refused",
		"network is unreachable",
		"no route to host",
		"connection timed out",
		"temporary failure in name resolution",
	}

	for _, networkErr := range networkErrorStrings {
		if strings.Contains(strings.ToLower(errStr), networkErr) {
			return true
		}
	}

	return false
}

// ParseTarget parses a target string and returns the type and parsed value
func ParseTarget(target string) (targetType string, parsed interface{}, err error) {
	// Try IP address first
	if ip := net.ParseIP(target); ip != nil {
		return "ip", ip, nil
	}

	// Try CIDR range
	if _, ipNet, err := net.ParseCIDR(target); err == nil {
		return "cidr", ipNet, nil
	}

	// Try hostname
	if isValidHostname(target) {
		return "hostname", target, nil
	}

	return "", nil, ValidationError{
		Field:   "target",
		Value:   target,
		Message: "target must be a valid IP address, hostname, or CIDR range",
	}
}

// ValidateTimeout validates that a timeout duration is reasonable
func ValidateTimeout(timeout time.Duration) error {
	if timeout <= 0 {
		return ValidationError{
			Field:   "timeout",
			Value:   timeout,
			Message: "timeout must be greater than 0",
		}
	}

	if timeout < 100*time.Millisecond {
		return ValidationError{
			Field:   "timeout",
			Value:   timeout,
			Message: "timeout should be at least 100ms for reliable results",
		}
	}

	if timeout > 5*time.Minute {
		return ValidationError{
			Field:   "timeout",
			Value:   timeout,
			Message: "timeout should not exceed 5 minutes to avoid hanging scans",
		}
	}

	return nil
}

// ValidateOutputFile validates that an output file path is writable
func ValidateOutputFile(filePath string) error {
	if filePath == "" {
		return nil // Empty path is valid (no file output)
	}

	// Check if the directory exists and is writable
	dir := filepath.Dir(filePath)
	if dir == "" {
		dir = "."
	}

	// Check if directory exists
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return ValidationError{
			Field:   "output_file",
			Value:   filePath,
			Message: fmt.Sprintf("output directory does not exist: %s", dir),
		}
	}

	// Check if we can write to the directory
	testFile := filepath.Join(dir, ".write_test")
	file, err := os.Create(testFile)
	if err != nil {
		return ValidationError{
			Field:   "output_file",
			Value:   filePath,
			Message: fmt.Sprintf("cannot write to output directory: %s", dir),
		}
	}
	file.Close()
	os.Remove(testFile)

	// Check if file already exists and is writable
	if _, err := os.Stat(filePath); err == nil {
		file, err := os.OpenFile(filePath, os.O_WRONLY, 0644)
		if err != nil {
			return ValidationError{
				Field:   "output_file",
				Value:   filePath,
				Message: "output file exists but is not writable",
			}
		}
		file.Close()
	}

	return nil
}

// ValidateOutputFormat validates that the output format is supported
func ValidateOutputFormat(format OutputFormat) error {
	switch format {
	case OutputFormatJSON, OutputFormatXML, OutputFormatText:
		return nil
	default:
		return ValidationError{
			Field:   "output_format",
			Value:   format,
			Message: "output format must be JSON (0), XML (1), or Text (2)",
		}
	}
}

// ValidateURL validates that a URL is properly formatted
func ValidateURL(urlStr string) error {
	if urlStr == "" {
		return ValidationError{
			Field:   "url",
			Value:   urlStr,
			Message: "URL cannot be empty",
		}
	}

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return ValidationError{
			Field:   "url",
			Value:   urlStr,
			Message: fmt.Sprintf("invalid URL format: %v", err),
		}
	}

	if parsedURL.Scheme == "" {
		return ValidationError{
			Field:   "url",
			Value:   urlStr,
			Message: "URL must include a scheme (http:// or https://)",
		}
	}

	if parsedURL.Host == "" {
		return ValidationError{
			Field:   "url",
			Value:   urlStr,
			Message: "URL must include a host",
		}
	}

	return nil
}

// ValidateRegex validates that a regular expression is valid
func ValidateRegex(pattern string) error {
	if pattern == "" {
		return nil // Empty pattern is valid
	}

	_, err := regexp.Compile(pattern)
	if err != nil {
		return ValidationError{
			Field:   "regex_pattern",
			Value:   pattern,
			Message: fmt.Sprintf("invalid regular expression: %v", err),
		}
	}

	return nil
}

// ValidateServiceSignature validates a service detection signature
func ValidateServiceSignature(sig ServiceSignature) error {
	// Validate port
	if !isValidPort(sig.Port) {
		return ValidationError{
			Field:   "service_signature.port",
			Value:   sig.Port,
			Message: "port must be between 1 and 65535",
		}
	}

	// Validate protocol
	if sig.Protocol != "tcp" && sig.Protocol != "udp" {
		return ValidationError{
			Field:   "service_signature.protocol",
			Value:   sig.Protocol,
			Message: "protocol must be 'tcp' or 'udp'",
		}
	}

	// Validate match regex
	if err := ValidateRegex(sig.Match); err != nil {
		return ValidationError{
			Field:   "service_signature.match",
			Value:   sig.Match,
			Message: fmt.Sprintf("invalid match regex: %v", err),
		}
	}

	// Validate version regex
	if err := ValidateRegex(sig.Version); err != nil {
		return ValidationError{
			Field:   "service_signature.version",
			Value:   sig.Version,
			Message: fmt.Sprintf("invalid version regex: %v", err),
		}
	}

	// Validate service name
	if sig.ServiceName == "" {
		return ValidationError{
			Field:   "service_signature.service_name",
			Value:   sig.ServiceName,
			Message: "service name cannot be empty",
		}
	}

	return nil
}

// ValidateScanProfile validates a scan profile configuration
func ValidateScanProfile(profile ScanProfile) error {
	// Validate name
	if profile.Name == "" {
		return ValidationError{
			Field:   "scan_profile.name",
			Value:   profile.Name,
			Message: "profile name cannot be empty",
		}
	}

	// Validate name format (alphanumeric, hyphens, underscores only)
	nameRegex := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	if !nameRegex.MatchString(profile.Name) {
		return ValidationError{
			Field:   "scan_profile.name",
			Value:   profile.Name,
			Message: "profile name can only contain letters, numbers, hyphens, and underscores",
		}
	}

	// Validate ports
	if err := ValidatePortRange(profile.Ports); err != nil {
		return err
	}

	// Validate scan type
	if profile.ScanType < 0 || profile.ScanType > 2 {
		return ValidationError{
			Field:   "scan_profile.scan_type",
			Value:   profile.ScanType,
			Message: "scan type must be TCP SYN (0), TCP Connect (1), or UDP (2)",
		}
	}

	// Validate timing profile
	if err := ValidateTimingProfile(profile.Timing); err != nil {
		return err
	}

	return nil
}

// ValidateTimingProfile validates timing configuration
func ValidateTimingProfile(timing TimingProfile) error {
	// Validate connect timeout
	if timing.ConnectTimeout <= 0 {
		return ValidationError{
			Field:   "timing_profile.connect_timeout",
			Value:   timing.ConnectTimeout,
			Message: "connect timeout must be greater than 0",
		}
	}

	if timing.ConnectTimeout > 1*time.Minute {
		return ValidationError{
			Field:   "timing_profile.connect_timeout",
			Value:   timing.ConnectTimeout,
			Message: "connect timeout should not exceed 1 minute",
		}
	}

	// Validate read timeout
	if timing.ReadTimeout <= 0 {
		return ValidationError{
			Field:   "timing_profile.read_timeout",
			Value:   timing.ReadTimeout,
			Message: "read timeout must be greater than 0",
		}
	}

	if timing.ReadTimeout > 1*time.Minute {
		return ValidationError{
			Field:   "timing_profile.read_timeout",
			Value:   timing.ReadTimeout,
			Message: "read timeout should not exceed 1 minute",
		}
	}

	// Validate delays (can be 0 for no delay)
	if timing.DelayBetweenPorts < 0 {
		return ValidationError{
			Field:   "timing_profile.delay_between_ports",
			Value:   timing.DelayBetweenPorts,
			Message: "delay between ports cannot be negative",
		}
	}

	if timing.DelayBetweenHosts < 0 {
		return ValidationError{
			Field:   "timing_profile.delay_between_hosts",
			Value:   timing.DelayBetweenHosts,
			Message: "delay between hosts cannot be negative",
		}
	}

	// Validate max retries
	if timing.MaxRetries < 0 {
		return ValidationError{
			Field:   "timing_profile.max_retries",
			Value:   timing.MaxRetries,
			Message: "max retries cannot be negative",
		}
	}

	if timing.MaxRetries > 10 {
		return ValidationError{
			Field:   "timing_profile.max_retries",
			Value:   timing.MaxRetries,
			Message: "max retries should not exceed 10 to avoid excessive delays",
		}
	}

	return nil
}

// ValidateResourceLimits validates resource limit configuration
func ValidateResourceLimits(limits ResourceLimits) error {
	// Validate max goroutines
	if limits.MaxGoroutines <= 0 {
		return ValidationError{
			Field:   "resource_limits.max_goroutines",
			Value:   limits.MaxGoroutines,
			Message: "max goroutines must be greater than 0",
		}
	}

	if limits.MaxGoroutines > 10000 {
		return ValidationError{
			Field:   "resource_limits.max_goroutines",
			Value:   limits.MaxGoroutines,
			Message: "max goroutines should not exceed 10000 to avoid system overload",
		}
	}

	// Validate max memory
	if limits.MaxMemoryMB <= 0 {
		return ValidationError{
			Field:   "resource_limits.max_memory_mb",
			Value:   limits.MaxMemoryMB,
			Message: "max memory must be greater than 0",
		}
	}

	if limits.MaxMemoryMB < 10 {
		return ValidationError{
			Field:   "resource_limits.max_memory_mb",
			Value:   limits.MaxMemoryMB,
			Message: "max memory should be at least 10 MB for basic operation",
		}
	}

	// Validate max connections
	if limits.MaxConnections <= 0 {
		return ValidationError{
			Field:   "resource_limits.max_connections",
			Value:   limits.MaxConnections,
			Message: "max connections must be greater than 0",
		}
	}

	if limits.MaxConnections > 5000 {
		return ValidationError{
			Field:   "resource_limits.max_connections",
			Value:   limits.MaxConnections,
			Message: "max connections should not exceed 5000 to avoid network flooding",
		}
	}

	// Validate timeouts
	if err := ValidateTimeout(limits.ScanTimeout); err != nil {
		return ValidationError{
			Field:   "resource_limits.scan_timeout",
			Value:   limits.ScanTimeout,
			Message: err.Error(),
		}
	}

	if limits.OverallTimeout <= 0 {
		return ValidationError{
			Field:   "resource_limits.overall_timeout",
			Value:   limits.OverallTimeout,
			Message: "overall timeout must be greater than 0",
		}
	}

	return nil
}

// SanitizeInput sanitizes user input to prevent injection attacks
func SanitizeInput(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")

	// Remove control characters except newline and tab
	var result strings.Builder
	for _, r := range input {
		if r >= 32 || r == '\n' || r == '\t' {
			result.WriteRune(r)
		}
	}

	return result.String()
}

// ValidateFilePath validates that a file path is safe and within allowed directories
func ValidateFilePath(filePath string, allowedDirs []string) error {
	if filePath == "" {
		return ValidationError{
			Field:   "file_path",
			Value:   filePath,
			Message: "file path cannot be empty",
		}
	}

	// Clean the path to resolve any .. or . components
	cleanPath := filepath.Clean(filePath)

	// Convert to absolute path
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return ValidationError{
			Field:   "file_path",
			Value:   filePath,
			Message: fmt.Sprintf("cannot resolve absolute path: %v", err),
		}
	}

	// Check if path is within allowed directories
	if len(allowedDirs) > 0 {
		allowed := false
		for _, allowedDir := range allowedDirs {
			absAllowedDir, err := filepath.Abs(allowedDir)
			if err != nil {
				continue
			}

			// Check if the file path is within the allowed directory
			relPath, err := filepath.Rel(absAllowedDir, absPath)
			if err == nil && !strings.HasPrefix(relPath, "..") {
				allowed = true
				break
			}
		}

		if !allowed {
			return ValidationError{
				Field:   "file_path",
				Value:   filePath,
				Message: "file path is not within allowed directories",
			}
		}
	}

	// Check for dangerous path components
	dangerousComponents := []string{
		"..",
		"~",
		"$",
	}

	for _, component := range dangerousComponents {
		if strings.Contains(cleanPath, component) {
			return ValidationError{
				Field:   "file_path",
				Value:   filePath,
				Message: fmt.Sprintf("file path contains dangerous component: %s", component),
			}
		}
	}

	return nil
}

// ValidateComprehensive performs comprehensive validation of all scan parameters
func ValidateComprehensive(config ScanConfig, limits ResourceLimits) error {
	// Basic scan config validation
	if err := ValidateScanConfig(config); err != nil {
		return err
	}

	// Timeout validation
	if err := ValidateTimeout(config.Timeout); err != nil {
		return err
	}

	// Output file validation
	if err := ValidateOutputFile(config.OutputFile); err != nil {
		return err
	}

	// Output format validation
	if err := ValidateOutputFormat(config.OutputFormat); err != nil {
		return err
	}

	// Resource limits validation
	if err := ValidateResourceLimits(limits); err != nil {
		return err
	}

	// Cross-validation: ensure scan config is compatible with resource limits
	if config.MaxThreads > limits.MaxConnections {
		return ValidationError{
			Field:   "max_threads",
			Value:   config.MaxThreads,
			Message: fmt.Sprintf("max threads (%d) exceeds connection limit (%d)", config.MaxThreads, limits.MaxConnections),
		}
	}

	if config.MaxThreads > limits.MaxGoroutines-10 { // Reserve some goroutines for overhead
		return ValidationError{
			Field:   "max_threads",
			Value:   config.MaxThreads,
			Message: fmt.Sprintf("max threads (%d) too close to goroutine limit (%d)", config.MaxThreads, limits.MaxGoroutines),
		}
	}

	return nil
}

// ValidateScanResult validates that a scan result contains all required information
// Implements Requirements 1.3, 3.3, 4.2
func ValidateScanResult(result *ScanResult) error {
	if result == nil {
		return ValidationError{
			Field:   "scan_result",
			Value:   nil,
			Message: "scan result cannot be nil",
		}
	}

	// Validate timestamp is present
	if result.Timestamp.IsZero() {
		return ValidationError{
			Field:   "timestamp",
			Value:   result.Timestamp,
			Message: "scan result must have a valid timestamp",
		}
	}

	// Validate scan configuration is present
	if err := ValidateScanConfig(result.ScanConfig); err != nil {
		return ValidationError{
			Field:   "scan_config",
			Value:   result.ScanConfig,
			Message: fmt.Sprintf("scan configuration validation failed: %v", err),
		}
	}

	// Validate host results
	if len(result.Hosts) == 0 {
		return ValidationError{
			Field:   "hosts",
			Value:   result.Hosts,
			Message: "scan result must contain at least one host result",
		}
	}

	for i, host := range result.Hosts {
		if err := ValidateHostResult(host, i); err != nil {
			return err
		}
	}

	// Validate statistics consistency
	if err := ValidateScanStatistics(result.Statistics, result.Hosts); err != nil {
		return err
	}

	return nil
}

// ValidateHostResult validates a single host result
// Implements Requirements 1.3, 3.3, 4.2
func ValidateHostResult(host HostResult, hostIndex int) error {
	// Validate target is present
	if host.Target == "" {
		return ValidationError{
			Field:   fmt.Sprintf("hosts[%d].target", hostIndex),
			Value:   host.Target,
			Message: "host target cannot be empty",
		}
	}

	// Validate host status
	if host.Status < HostUp || host.Status > HostUnknown {
		return ValidationError{
			Field:   fmt.Sprintf("hosts[%d].status", hostIndex),
			Value:   host.Status,
			Message: "host status must be up, down, or unknown",
		}
	}

	// Validate response time is non-negative
	if host.ResponseTime < 0 {
		return ValidationError{
			Field:   fmt.Sprintf("hosts[%d].response_time", hostIndex),
			Value:   host.ResponseTime,
			Message: "host response time cannot be negative",
		}
	}

	// Validate port results (Requirements 1.3)
	for j, port := range host.Ports {
		if err := ValidatePortResult(port, hostIndex, j); err != nil {
			return err
		}
	}

	// Validate OS information if present (Requirements 4.2)
	if host.OS.Family != "" || host.OS.Version != "" || len(host.OS.Matches) > 0 {
		if err := ValidateOSInfo(host.OS, hostIndex); err != nil {
			return err
		}
	}

	return nil
}

// ValidatePortResult validates a single port result
// Implements Requirements 1.3, 3.3
func ValidatePortResult(port PortResult, hostIndex, portIndex int) error {
	// Requirement 1.3: Port number must be present and valid
	if port.Port < 1 || port.Port > 65535 {
		return ValidationError{
			Field:   fmt.Sprintf("hosts[%d].ports[%d].port", hostIndex, portIndex),
			Value:   port.Port,
			Message: "port number must be between 1 and 65535",
		}
	}

	// Requirement 1.3: Protocol must be present and valid
	if port.Protocol == "" {
		return ValidationError{
			Field:   fmt.Sprintf("hosts[%d].ports[%d].protocol", hostIndex, portIndex),
			Value:   port.Protocol,
			Message: "port protocol cannot be empty",
		}
	}

	if port.Protocol != "tcp" && port.Protocol != "udp" {
		return ValidationError{
			Field:   fmt.Sprintf("hosts[%d].ports[%d].protocol", hostIndex, portIndex),
			Value:   port.Protocol,
			Message: "port protocol must be 'tcp' or 'udp'",
		}
	}

	// Requirement 1.3: State must be present and valid
	if port.State < PortOpen || port.State > PortFiltered {
		return ValidationError{
			Field:   fmt.Sprintf("hosts[%d].ports[%d].state", hostIndex, portIndex),
			Value:   port.State,
			Message: "port state must be open, closed, or filtered",
		}
	}

	// Response time should be non-negative
	if port.ResponseTime < 0 {
		return ValidationError{
			Field:   fmt.Sprintf("hosts[%d].ports[%d].response_time", hostIndex, portIndex),
			Value:   port.ResponseTime,
			Message: "port response time cannot be negative",
		}
	}

	// Validate service information if present (Requirements 3.3)
	if port.Service.Name != "" || port.Service.Version != "" || port.Service.Product != "" {
		if err := ValidateServiceInfo(port.Service, hostIndex, portIndex); err != nil {
			return err
		}
	}

	return nil
}

// ValidateServiceInfo validates service detection information
// Implements Requirements 3.3
func ValidateServiceInfo(service ServiceInfo, hostIndex, portIndex int) error {
	// Requirement 3.3: Service name, version, and additional details should be present when detected

	// Confidence should be between 0 and 100
	if service.Confidence < 0 || service.Confidence > 100 {
		return ValidationError{
			Field:   fmt.Sprintf("hosts[%d].ports[%d].service.confidence", hostIndex, portIndex),
			Value:   service.Confidence,
			Message: "service confidence must be between 0 and 100",
		}
	}

	// If service is detected, name should not be empty
	if service.Name == "" && (service.Version != "" || service.Product != "" || service.Confidence > 0) {
		return ValidationError{
			Field:   fmt.Sprintf("hosts[%d].ports[%d].service.name", hostIndex, portIndex),
			Value:   service.Name,
			Message: "service name cannot be empty when other service details are present",
		}
	}

	// Validate extra info key-value pairs
	for k, kv := range service.ExtraInfo {
		if kv.Key == "" {
			return ValidationError{
				Field:   fmt.Sprintf("hosts[%d].ports[%d].service.extra_info[%d].key", hostIndex, portIndex, k),
				Value:   kv.Key,
				Message: "extra info key cannot be empty",
			}
		}
	}

	return nil
}

// ValidateOSInfo validates operating system detection information
// Implements Requirements 4.2
func ValidateOSInfo(os OSInfo, hostIndex int) error {
	// Requirement 4.2: OS family, version, and confidence level should be present when detected

	// Confidence should be between 0 and 100
	if os.Confidence < 0 || os.Confidence > 100 {
		return ValidationError{
			Field:   fmt.Sprintf("hosts[%d].os.confidence", hostIndex),
			Value:   os.Confidence,
			Message: "OS confidence must be between 0 and 100",
		}
	}

	// Validate OS matches
	for i, match := range os.Matches {
		if match.Name == "" {
			return ValidationError{
				Field:   fmt.Sprintf("hosts[%d].os.matches[%d].name", hostIndex, i),
				Value:   match.Name,
				Message: "OS match name cannot be empty",
			}
		}

		if match.Confidence < 0 || match.Confidence > 100 {
			return ValidationError{
				Field:   fmt.Sprintf("hosts[%d].os.matches[%d].confidence", hostIndex, i),
				Value:   match.Confidence,
				Message: "OS match confidence must be between 0 and 100",
			}
		}
	}

	return nil
}

// ValidateScanStatistics validates scan statistics consistency
func ValidateScanStatistics(stats ScanStatistics, hosts []HostResult) error {
	// Validate counts are non-negative
	if stats.HostsScanned < 0 {
		return ValidationError{
			Field:   "statistics.hosts_scanned",
			Value:   stats.HostsScanned,
			Message: "hosts scanned count cannot be negative",
		}
	}

	if stats.HostsTotal < 0 {
		return ValidationError{
			Field:   "statistics.hosts_total",
			Value:   stats.HostsTotal,
			Message: "hosts total count cannot be negative",
		}
	}

	if stats.PortsScanned < 0 {
		return ValidationError{
			Field:   "statistics.ports_scanned",
			Value:   stats.PortsScanned,
			Message: "ports scanned count cannot be negative",
		}
	}

	if stats.PortsTotal < 0 {
		return ValidationError{
			Field:   "statistics.ports_total",
			Value:   stats.PortsTotal,
			Message: "ports total count cannot be negative",
		}
	}

	if stats.OpenPorts < 0 {
		return ValidationError{
			Field:   "statistics.open_ports",
			Value:   stats.OpenPorts,
			Message: "open ports count cannot be negative",
		}
	}

	if stats.ClosedPorts < 0 {
		return ValidationError{
			Field:   "statistics.closed_ports",
			Value:   stats.ClosedPorts,
			Message: "closed ports count cannot be negative",
		}
	}

	if stats.FilteredPorts < 0 {
		return ValidationError{
			Field:   "statistics.filtered_ports",
			Value:   stats.FilteredPorts,
			Message: "filtered ports count cannot be negative",
		}
	}

	// Validate consistency between statistics and actual results
	actualOpenPorts := 0
	actualClosedPorts := 0
	actualFilteredPorts := 0
	actualTotalPorts := 0

	for _, host := range hosts {
		for _, port := range host.Ports {
			actualTotalPorts++
			switch port.State {
			case PortOpen:
				actualOpenPorts++
			case PortClosed:
				actualClosedPorts++
			case PortFiltered:
				actualFilteredPorts++
			}
		}
	}

	// Check consistency (allow some tolerance for partial scans)
	if stats.OpenPorts != actualOpenPorts {
		return ValidationError{
			Field:   "statistics.open_ports",
			Value:   stats.OpenPorts,
			Message: fmt.Sprintf("open ports count (%d) does not match actual open ports (%d)", stats.OpenPorts, actualOpenPorts),
		}
	}

	if stats.ClosedPorts != actualClosedPorts {
		return ValidationError{
			Field:   "statistics.closed_ports",
			Value:   stats.ClosedPorts,
			Message: fmt.Sprintf("closed ports count (%d) does not match actual closed ports (%d)", stats.ClosedPorts, actualClosedPorts),
		}
	}

	if stats.FilteredPorts != actualFilteredPorts {
		return ValidationError{
			Field:   "statistics.filtered_ports",
			Value:   stats.FilteredPorts,
			Message: fmt.Sprintf("filtered ports count (%d) does not match actual filtered ports (%d)", stats.FilteredPorts, actualFilteredPorts),
		}
	}

	// Validate timing information
	if !stats.StartTime.IsZero() && !stats.EndTime.IsZero() {
		if stats.EndTime.Before(stats.StartTime) {
			return ValidationError{
				Field:   "statistics.end_time",
				Value:   stats.EndTime,
				Message: "end time cannot be before start time",
			}
		}

		expectedElapsed := stats.EndTime.Sub(stats.StartTime)
		if stats.ElapsedTime != expectedElapsed {
			return ValidationError{
				Field:   "statistics.elapsed_time",
				Value:   stats.ElapsedTime,
				Message: fmt.Sprintf("elapsed time (%v) does not match start/end time difference (%v)", stats.ElapsedTime, expectedElapsed),
			}
		}
	}

	// Validate scan rate
	if stats.ScanRate < 0 {
		return ValidationError{
			Field:   "statistics.scan_rate",
			Value:   stats.ScanRate,
			Message: "scan rate cannot be negative",
		}
	}

	return nil
}

// GenerateScanResultSummary generates a summary of scan results
// Implements Requirements 1.3, 3.3, 4.2
func GenerateScanResultSummary(result *ScanResult) (*ScanResultSummary, error) {
	if result == nil {
		return nil, ValidationError{
			Field:   "scan_result",
			Value:   nil,
			Message: "scan result cannot be nil",
		}
	}

	// Validate the result first
	if err := ValidateScanResult(result); err != nil {
		return nil, fmt.Errorf("scan result validation failed: %w", err)
	}

	summary := &ScanResultSummary{
		Timestamp:     result.Timestamp,
		ScanDuration:  result.Statistics.ElapsedTime,
		TotalHosts:    len(result.Hosts),
		HostsUp:       0,
		HostsDown:     0,
		TotalPorts:    result.Statistics.PortsScanned,
		OpenPorts:     result.Statistics.OpenPorts,
		ClosedPorts:   result.Statistics.ClosedPorts,
		FilteredPorts: result.Statistics.FilteredPorts,
		ServicesFound: make(map[string]int),
		OSDetected:    make(map[string]int),
		TopPorts:      make([]PortSummary, 0),
	}

	// Count host statuses and collect service/OS information
	portCounts := make(map[int]int)

	for _, host := range result.Hosts {
		switch host.Status {
		case HostUp:
			summary.HostsUp++
		case HostDown:
			summary.HostsDown++
		}

		// Count services
		for _, port := range host.Ports {
			if port.State == PortOpen {
				portCounts[port.Port]++

				if port.Service.Name != "" {
					summary.ServicesFound[port.Service.Name]++
				}
			}
		}

		// Count OS detections
		if host.OS.Family != "" {
			osKey := host.OS.Family
			if host.OS.Version != "" {
				osKey += " " + host.OS.Version
			}
			summary.OSDetected[osKey]++
		}
	}

	// Generate top ports list (top 10 most common open ports)
	type portCount struct {
		port  int
		count int
	}

	var portList []portCount
	for port, count := range portCounts {
		portList = append(portList, portCount{port: port, count: count})
	}

	// Sort by count (descending)
	for i := 0; i < len(portList)-1; i++ {
		for j := i + 1; j < len(portList); j++ {
			if portList[j].count > portList[i].count {
				portList[i], portList[j] = portList[j], portList[i]
			}
		}
	}

	// Take top 10
	maxPorts := 10
	if len(portList) < maxPorts {
		maxPorts = len(portList)
	}

	for i := 0; i < maxPorts; i++ {
		summary.TopPorts = append(summary.TopPorts, PortSummary{
			Port:  portList[i].port,
			Count: portList[i].count,
		})
	}

	return summary, nil
}

// ScanResultSummary provides a high-level summary of scan results
type ScanResultSummary struct {
	Timestamp     time.Time      `json:"timestamp"`
	ScanDuration  time.Duration  `json:"scan_duration"`
	TotalHosts    int            `json:"total_hosts"`
	HostsUp       int            `json:"hosts_up"`
	HostsDown     int            `json:"hosts_down"`
	TotalPorts    int            `json:"total_ports"`
	OpenPorts     int            `json:"open_ports"`
	ClosedPorts   int            `json:"closed_ports"`
	FilteredPorts int            `json:"filtered_ports"`
	ServicesFound map[string]int `json:"services_found"`
	OSDetected    map[string]int `json:"os_detected"`
	TopPorts      []PortSummary  `json:"top_ports"`
}

// PortSummary represents a port and how many hosts it was found open on
type PortSummary struct {
	Port  int `json:"port"`
	Count int `json:"count"`
}
