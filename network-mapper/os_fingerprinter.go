package networkmapper

import (
	"context"
	"fmt"
	"log"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DefaultOSFingerprinter implements the OSFingerprinter interface
type DefaultOSFingerprinter struct {
	timeout    time.Duration
	maxRetries int
	logger     *log.Logger
	signatures []OSSignature
}

// OSSignature represents an OS fingerprinting signature
type OSSignature struct {
	Name       string            // OS name
	Version    string            // OS version pattern
	Family     string            // OS family (Linux, Windows, etc.)
	Patterns   []FingerprintTest // Tests to perform
	Confidence float64           // Base confidence for this signature
}

// FingerprintTest represents a single fingerprinting test
type FingerprintTest struct {
	Type        string  // Type of test (tcp_window, tcp_options, icmp_reply, etc.)
	Pattern     string  // Pattern to match
	Weight      float64 // Weight of this test in overall confidence
	Description string  // Human-readable description
}

// NewDefaultOSFingerprinter creates a new OS fingerprinter with default settings
func NewDefaultOSFingerprinter(timeout time.Duration, maxRetries int, logger *log.Logger) *DefaultOSFingerprinter {
	if logger == nil {
		logger = log.Default()
	}

	fingerprinter := &DefaultOSFingerprinter{
		timeout:    timeout,
		maxRetries: maxRetries,
		logger:     logger,
		signatures: getDefaultOSSignatures(),
	}

	return fingerprinter
}

// DetectOS attempts to identify the operating system of a target
func (osf *DefaultOSFingerprinter) DetectOS(ctx context.Context, target string, openPorts []int) OSInfo {
	osf.logger.Printf("Starting OS detection for target: %s with %d open ports", target, len(openPorts))

	if len(openPorts) == 0 {
		osf.logger.Printf("No open ports available for OS detection on target: %s", target)
		return OSInfo{
			Family:     "Unknown",
			Version:    "Unknown",
			Matches:    []OSMatch{},
			Confidence: 0.0,
		}
	}

	// Perform various fingerprinting tests
	results := osf.performFingerprintingTests(ctx, target, openPorts)

	// Analyze results against known signatures
	matches := osf.analyzeFingerprints(results)

	// Return the best match or unknown if confidence is too low
	if len(matches) == 0 {
		return OSInfo{
			Family:     "Unknown",
			Version:    "Unknown",
			Matches:    []OSMatch{},
			Confidence: 0.0,
		}
	}

	// Sort matches by confidence (highest first)
	for i := 0; i < len(matches)-1; i++ {
		for j := i + 1; j < len(matches); j++ {
			if matches[i].Confidence < matches[j].Confidence {
				matches[i], matches[j] = matches[j], matches[i]
			}
		}
	}

	bestMatch := matches[0]
	osf.logger.Printf("OS detection completed for %s: %s (confidence: %.2f%%)", target, bestMatch.Name, bestMatch.Confidence)

	return OSInfo{
		Family:     extractOSFamily(bestMatch.Name),
		Version:    bestMatch.Version,
		Matches:    matches,
		Confidence: bestMatch.Confidence,
	}
}

// performFingerprintingTests performs various TCP/IP stack analysis tests
func (osf *DefaultOSFingerprinter) performFingerprintingTests(ctx context.Context, target string, openPorts []int) map[string]string {
	results := make(map[string]string)

	// Use the first open port for testing
	testPort := openPorts[0]

	// Test TCP window size
	if windowSize := osf.getTCPWindowSize(ctx, target, testPort); windowSize > 0 {
		results["tcp_window"] = strconv.Itoa(windowSize)
	}

	// Test TCP options
	if options := osf.getTCPOptions(ctx, target, testPort); options != "" {
		results["tcp_options"] = options
	}

	// Test TCP initial sequence number patterns
	if seqPattern := osf.getTCPSequencePattern(ctx, target, testPort); seqPattern != "" {
		results["tcp_sequence"] = seqPattern
	}

	// Test TTL values
	if ttl := osf.getTTLValue(ctx, target); ttl > 0 {
		results["ttl"] = strconv.Itoa(ttl)
	}

	// Test TCP timestamp behavior
	if timestamp := osf.getTCPTimestamp(ctx, target, testPort); timestamp != "" {
		results["tcp_timestamp"] = timestamp
	}

	return results
}

// getTCPWindowSize attempts to determine the TCP window size
func (osf *DefaultOSFingerprinter) getTCPWindowSize(ctx context.Context, target string, port int) int {
	// This is a simplified implementation
	// In a real implementation, you would use raw sockets to analyze TCP packets
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), osf.timeout)
	if err != nil {
		return 0
	}
	defer conn.Close()

	// For demonstration purposes, we'll return different values based on common patterns
	// Real implementation would analyze actual TCP window advertisements
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn // Use the connection for actual analysis
		// This would involve raw socket programming to inspect TCP headers
		// For now, return a placeholder value
		return 65535 // Common default window size
	}

	return 0
}

// getTCPOptions attempts to analyze TCP options
func (osf *DefaultOSFingerprinter) getTCPOptions(ctx context.Context, target string, port int) string {
	// This would analyze TCP options like MSS, window scaling, timestamps, etc.
	// Simplified implementation for demonstration
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), osf.timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Real implementation would use raw sockets to inspect TCP options
	// Return placeholder indicating basic TCP support
	return "mss,nop,wscale,nop,nop,timestamp"
}

// getTCPSequencePattern analyzes TCP sequence number patterns
func (osf *DefaultOSFingerprinter) getTCPSequencePattern(ctx context.Context, target string, port int) string {
	// This would analyze how the target generates TCP sequence numbers
	// Different OS implementations have different patterns

	// Simplified implementation - would need multiple connections to analyze patterns
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), osf.timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Real implementation would establish multiple connections and analyze sequence number increments
	return "random" // Most modern systems use random sequence numbers
}

// getTTLValue attempts to determine the initial TTL value
func (osf *DefaultOSFingerprinter) getTTLValue(ctx context.Context, target string) int {
	// This would use ICMP or analyze TCP packets to determine TTL
	// Different operating systems use different default TTL values

	// Simplified implementation using ping-like approach
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:80", target), osf.timeout)
	if err != nil {
		// Try common ports if 80 fails
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:22", target), osf.timeout)
		if err != nil {
			return 0
		}
	}
	defer conn.Close()

	// Real implementation would extract TTL from IP headers
	// Common TTL values: Linux=64, Windows=128, Cisco=255
	return 64 // Placeholder - would be extracted from actual packets
}

// getTCPTimestamp analyzes TCP timestamp behavior
func (osf *DefaultOSFingerprinter) getTCPTimestamp(ctx context.Context, target string, port int) string {
	// This would analyze how the target handles TCP timestamps
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), osf.timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Real implementation would analyze timestamp options in TCP headers
	return "supported" // Placeholder
}

// analyzeFingerprints compares test results against known OS signatures
func (osf *DefaultOSFingerprinter) analyzeFingerprints(results map[string]string) []OSMatch {
	var matches []OSMatch

	for _, signature := range osf.signatures {
		confidence := osf.calculateSignatureMatch(signature, results)
		if confidence > 10.0 { // Only include matches with reasonable confidence
			matches = append(matches, OSMatch{
				Name:       signature.Name,
				Version:    signature.Version,
				Confidence: confidence,
			})
		}
	}

	return matches
}

// calculateSignatureMatch calculates how well the results match a signature
func (osf *DefaultOSFingerprinter) calculateSignatureMatch(signature OSSignature, results map[string]string) float64 {
	totalWeight := 0.0
	matchedWeight := 0.0

	for _, test := range signature.Patterns {
		totalWeight += test.Weight

		if result, exists := results[test.Type]; exists {
			if osf.matchesPattern(result, test.Pattern) {
				matchedWeight += test.Weight
			}
		}
	}

	if totalWeight == 0 {
		return 0.0
	}

	// Calculate base confidence from pattern matching
	baseConfidence := (matchedWeight / totalWeight) * 100.0

	// Apply signature base confidence
	finalConfidence := baseConfidence * (signature.Confidence / 100.0)

	return math.Min(finalConfidence, 100.0)
}

// matchesPattern checks if a result matches a pattern
func (osf *DefaultOSFingerprinter) matchesPattern(result, pattern string) bool {
	// Handle exact matches
	if result == pattern {
		return true
	}

	// Handle regex patterns
	if strings.HasPrefix(pattern, "regex:") {
		regexPattern := strings.TrimPrefix(pattern, "regex:")
		matched, err := regexp.MatchString(regexPattern, result)
		if err != nil {
			osf.logger.Printf("Invalid regex pattern: %s", regexPattern)
			return false
		}
		return matched
	}

	// Handle range patterns (e.g., "60-70" for TTL ranges)
	if strings.Contains(pattern, "-") {
		parts := strings.Split(pattern, "-")
		if len(parts) == 2 {
			min, err1 := strconv.Atoi(parts[0])
			max, err2 := strconv.Atoi(parts[1])
			val, err3 := strconv.Atoi(result)
			if err1 == nil && err2 == nil && err3 == nil {
				return val >= min && val <= max
			}
		}
	}

	return false
}

// extractOSFamily extracts the OS family from an OS name
func extractOSFamily(osName string) string {
	osName = strings.ToLower(osName)

	if strings.Contains(osName, "linux") || strings.Contains(osName, "ubuntu") ||
		strings.Contains(osName, "debian") || strings.Contains(osName, "centos") ||
		strings.Contains(osName, "redhat") || strings.Contains(osName, "fedora") {
		return "Linux"
	}

	if strings.Contains(osName, "windows") || strings.Contains(osName, "win") {
		return "Windows"
	}

	if strings.Contains(osName, "macos") || strings.Contains(osName, "darwin") ||
		strings.Contains(osName, "osx") {
		return "macOS"
	}

	if strings.Contains(osName, "freebsd") {
		return "FreeBSD"
	}

	if strings.Contains(osName, "openbsd") {
		return "OpenBSD"
	}

	if strings.Contains(osName, "netbsd") {
		return "NetBSD"
	}

	if strings.Contains(osName, "solaris") || strings.Contains(osName, "sunos") {
		return "Solaris"
	}

	return "Unknown"
}

// getDefaultOSSignatures returns a database of OS fingerprinting signatures
func getDefaultOSSignatures() []OSSignature {
	return []OSSignature{
		{
			Name:       "Linux 2.6.x",
			Version:    "2.6.x",
			Family:     "Linux",
			Confidence: 85.0,
			Patterns: []FingerprintTest{
				{Type: "tcp_window", Pattern: "5840", Weight: 20.0, Description: "Linux default window size"},
				{Type: "ttl", Pattern: "64", Weight: 25.0, Description: "Linux default TTL"},
				{Type: "tcp_options", Pattern: "regex:.*mss.*wscale.*timestamp.*", Weight: 30.0, Description: "Linux TCP options"},
				{Type: "tcp_sequence", Pattern: "random", Weight: 25.0, Description: "Random sequence numbers"},
			},
		},
		{
			Name:       "Linux 3.x/4.x/5.x",
			Version:    "3.x-5.x",
			Family:     "Linux",
			Confidence: 90.0,
			Patterns: []FingerprintTest{
				{Type: "tcp_window", Pattern: "29200", Weight: 20.0, Description: "Modern Linux window size"},
				{Type: "ttl", Pattern: "64", Weight: 25.0, Description: "Linux default TTL"},
				{Type: "tcp_options", Pattern: "regex:.*mss.*wscale.*timestamp.*", Weight: 30.0, Description: "Linux TCP options"},
				{Type: "tcp_sequence", Pattern: "random", Weight: 25.0, Description: "Random sequence numbers"},
			},
		},
		{
			Name:       "Windows 10/11",
			Version:    "10/11",
			Family:     "Windows",
			Confidence: 88.0,
			Patterns: []FingerprintTest{
				{Type: "tcp_window", Pattern: "65535", Weight: 20.0, Description: "Windows default window size"},
				{Type: "ttl", Pattern: "128", Weight: 30.0, Description: "Windows default TTL"},
				{Type: "tcp_options", Pattern: "regex:.*mss.*nop.*wscale.*", Weight: 25.0, Description: "Windows TCP options"},
				{Type: "tcp_sequence", Pattern: "random", Weight: 25.0, Description: "Random sequence numbers"},
			},
		},
		{
			Name:       "Windows Server 2016/2019/2022",
			Version:    "Server 2016-2022",
			Family:     "Windows",
			Confidence: 85.0,
			Patterns: []FingerprintTest{
				{Type: "tcp_window", Pattern: "65535", Weight: 20.0, Description: "Windows Server window size"},
				{Type: "ttl", Pattern: "128", Weight: 30.0, Description: "Windows default TTL"},
				{Type: "tcp_options", Pattern: "regex:.*mss.*nop.*wscale.*", Weight: 25.0, Description: "Windows TCP options"},
				{Type: "tcp_sequence", Pattern: "random", Weight: 25.0, Description: "Random sequence numbers"},
			},
		},
		{
			Name:       "macOS",
			Version:    "10.x-13.x",
			Family:     "macOS",
			Confidence: 82.0,
			Patterns: []FingerprintTest{
				{Type: "tcp_window", Pattern: "65535", Weight: 20.0, Description: "macOS window size"},
				{Type: "ttl", Pattern: "64", Weight: 25.0, Description: "macOS default TTL"},
				{Type: "tcp_options", Pattern: "regex:.*mss.*nop.*wscale.*timestamp.*", Weight: 30.0, Description: "macOS TCP options"},
				{Type: "tcp_sequence", Pattern: "random", Weight: 25.0, Description: "Random sequence numbers"},
			},
		},
		{
			Name:       "FreeBSD",
			Version:    "12.x-14.x",
			Family:     "FreeBSD",
			Confidence: 80.0,
			Patterns: []FingerprintTest{
				{Type: "tcp_window", Pattern: "65535", Weight: 20.0, Description: "FreeBSD window size"},
				{Type: "ttl", Pattern: "64", Weight: 25.0, Description: "FreeBSD default TTL"},
				{Type: "tcp_options", Pattern: "regex:.*mss.*nop.*wscale.*", Weight: 30.0, Description: "FreeBSD TCP options"},
				{Type: "tcp_sequence", Pattern: "random", Weight: 25.0, Description: "Random sequence numbers"},
			},
		},
		{
			Name:       "Cisco IOS",
			Version:    "12.x-15.x",
			Family:     "Cisco IOS",
			Confidence: 75.0,
			Patterns: []FingerprintTest{
				{Type: "tcp_window", Pattern: "4128", Weight: 25.0, Description: "Cisco IOS window size"},
				{Type: "ttl", Pattern: "255", Weight: 35.0, Description: "Cisco default TTL"},
				{Type: "tcp_options", Pattern: "regex:.*mss.*", Weight: 20.0, Description: "Basic TCP options"},
				{Type: "tcp_sequence", Pattern: "incremental", Weight: 20.0, Description: "Incremental sequence numbers"},
			},
		},
	}
}
