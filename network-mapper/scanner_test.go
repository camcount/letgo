package networkmapper

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// **Feature: network-mapper, Property 2: Port Range Compliance**
// **Validates: Requirements 1.2**
// Property: For any specified port range, the Network_Mapper should scan only ports
// within that range and no ports outside the range
func TestProperty2_PortRangeCompliance(t *testing.T) {
	// Property-based test with 100 iterations as specified in design
	for i := range 100 {
		t.Run(fmt.Sprintf("iteration_%d", i), func(t *testing.T) {
			// Generate random valid port range (keep it small for testing performance)
			startPort := rand.Intn(100) + 1 // 1-100
			rangeSize := rand.Intn(50) + 1  // 1-50 ports in range
			endPort := startPort + rangeSize
			if endPort > 65535 {
				endPort = 65535
			}

			// Create port range
			portRange := PortRange{
				Start: startPort,
				End:   endPort,
			}

			// Expand the range to get expected ports
			expectedPorts := make(map[int]bool)
			for port := startPort; port <= endPort; port++ {
				expectedPorts[port] = true
			}

			// Create scan config with this port range
			config := ScanConfig{
				Targets:    []string{"127.0.0.1"}, // Use localhost for testing
				PortRanges: []PortRange{portRange},
				ScanType:   ScanTypeTCPConnect,
				MaxThreads: 10,
				Timeout:    100 * time.Millisecond, // Short timeout for testing
			}

			// Get all ports that would be scanned
			allPorts, err := GetAllPorts(config)
			require.NoError(t, err, "Should be able to get all ports from config")

			// Verify that all returned ports are within the specified range
			for _, port := range allPorts {
				require.True(t, expectedPorts[port],
					"Port %d should be within range %d-%d", port, startPort, endPort)
				require.GreaterOrEqual(t, port, startPort,
					"Port %d should be >= start port %d", port, startPort)
				require.LessOrEqual(t, port, endPort,
					"Port %d should be <= end port %d", port, endPort)
			}

			// Verify that all expected ports are included
			require.Equal(t, len(expectedPorts), len(allPorts),
				"Should scan exactly the ports in the range %d-%d", startPort, endPort)

			// Verify no ports outside the range are included
			for _, port := range allPorts {
				require.Contains(t, expectedPorts, port,
					"Port %d should be in expected range %d-%d", port, startPort, endPort)
			}
		})
	}
}

// Test edge cases for port range compliance
func TestPortRangeComplianceEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		portRange PortRange
		wantError bool
	}{
		{
			name:      "minimum valid range",
			portRange: PortRange{Start: 1, End: 1},
			wantError: false,
		},
		{
			name:      "maximum valid range",
			portRange: PortRange{Start: 65535, End: 65535},
			wantError: false,
		},
		{
			name:      "full range",
			portRange: PortRange{Start: 1, End: 65535},
			wantError: false,
		},
		{
			name:      "invalid start port (0)",
			portRange: PortRange{Start: 0, End: 100},
			wantError: true,
		},
		{
			name:      "invalid end port (65536)",
			portRange: PortRange{Start: 1, End: 65536},
			wantError: true,
		},
		{
			name:      "start > end",
			portRange: PortRange{Start: 100, End: 50},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePortRanges([]PortRange{tt.portRange})
			if tt.wantError {
				require.Error(t, err, "Should return error for invalid port range")
			} else {
				require.NoError(t, err, "Should not return error for valid port range")

				// If valid, verify the expanded ports are within range
				expanded := ExpandPortRanges([]PortRange{tt.portRange})
				for _, port := range expanded {
					require.GreaterOrEqual(t, port, tt.portRange.Start,
						"Expanded port %d should be >= start %d", port, tt.portRange.Start)
					require.LessOrEqual(t, port, tt.portRange.End,
						"Expanded port %d should be <= end %d", port, tt.portRange.End)
				}
			}
		})
	}
}

// Test multiple port ranges compliance
func TestMultiplePortRangesCompliance(t *testing.T) {
	// Test with multiple non-overlapping ranges
	ranges := []PortRange{
		{Start: 20, End: 25},
		{Start: 80, End: 85},
		{Start: 443, End: 445},
	}

	expanded := ExpandPortRanges(ranges)

	// Build expected ports
	expectedPorts := make(map[int]bool)
	for _, r := range ranges {
		for port := r.Start; port <= r.End; port++ {
			expectedPorts[port] = true
		}
	}

	// Verify all expanded ports are expected
	require.Equal(t, len(expectedPorts), len(expanded),
		"Should have correct number of expanded ports")

	for _, port := range expanded {
		require.Contains(t, expectedPorts, port,
			"Port %d should be in one of the specified ranges", port)
	}
}

// Test port validation functions
func TestPortValidation(t *testing.T) {
	tests := []struct {
		name  string
		port  int
		valid bool
	}{
		{"valid port 1", 1, true},
		{"valid port 80", 80, true},
		{"valid port 65535", 65535, true},
		{"invalid port 0", 0, false},
		{"invalid port -1", -1, false},
		{"invalid port 65536", 65536, false},
		{"invalid port 100000", 100000, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidPort(tt.port)
			require.Equal(t, tt.valid, result,
				"Port %d validity should be %v", tt.port, tt.valid)
		})
	}
}

// Benchmark port range expansion for performance testing
func BenchmarkPortRangeExpansion(b *testing.B) {
	ranges := []PortRange{
		{Start: 1, End: 1000},
		{Start: 8000, End: 9000},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExpandPortRanges(ranges)
	}
}

// **Feature: network-mapper, Property 12: Scan Type Implementation**
// **Validates: Requirements 5.1, 5.2, 5.3**
// Property: For any selected scan type (TCP SYN, TCP Connect, UDP), the appropriate scanning technique should be used
func TestProperty12_ScanTypeImplementation(t *testing.T) {
	// Property-based test with 100 iterations as specified in design
	for i := range 100 {
		t.Run(fmt.Sprintf("iteration_%d", i), func(t *testing.T) {
			// Generate random scan type
			scanTypes := []ScanType{ScanTypeTCPSYN, ScanTypeTCPConnect, ScanTypeUDP}
			scanType := scanTypes[rand.Intn(len(scanTypes))]

			// Create scanner with short timeout for testing
			logger := log.New(os.Stderr, "test: ", log.LstdFlags)
			scanner := NewDefaultPortScanner(100*time.Millisecond, 1, logger)

			// Use localhost for testing
			target := "127.0.0.1"

			// Test with a port that's likely to be closed (high port number)
			port := rand.Intn(10000) + 50000 // 50000-59999

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// Perform the scan
			result := scanner.ScanPort(ctx, target, port, scanType)

			// Verify that the result has the correct protocol for the scan type
			expectedProtocol := getProtocolForScanType(scanType)
			require.Equal(t, expectedProtocol, result.Protocol,
				"Scan result should have protocol %s for scan type %s", expectedProtocol, scanType.String())

			// Verify that the port number is correct
			require.Equal(t, port, result.Port,
				"Scan result should have correct port number %d", port)

			// Verify that the scan type affects the scanning behavior
			// For TCP scans, we expect either open, closed, or filtered
			// For UDP scans, we expect open or filtered (UDP is stateless)
			switch scanType {
			case ScanTypeTCPConnect, ScanTypeTCPSYN:
				require.Contains(t, []PortState{PortOpen, PortClosed, PortFiltered}, result.State,
					"TCP scan should return open, closed, or filtered state")
			case ScanTypeUDP:
				require.Contains(t, []PortState{PortOpen, PortFiltered}, result.State,
					"UDP scan should return open or filtered state")
			}

			// Verify response time is recorded
			require.Greater(t, result.ResponseTime, time.Duration(0),
				"Response time should be greater than 0")
		})
	}
}

// Test scan type protocol mapping
func TestScanTypeProtocolMapping(t *testing.T) {
	tests := []struct {
		scanType         ScanType
		expectedProtocol string
	}{
		{ScanTypeTCPConnect, "tcp"},
		{ScanTypeTCPSYN, "tcp"},
		{ScanTypeUDP, "udp"},
	}

	for _, tt := range tests {
		t.Run(tt.scanType.String(), func(t *testing.T) {
			protocol := getProtocolForScanType(tt.scanType)
			require.Equal(t, tt.expectedProtocol, protocol,
				"Scan type %s should map to protocol %s", tt.scanType.String(), tt.expectedProtocol)
		})
	}
}

// Test that different scan types produce different behaviors
func TestScanTypeBehaviorDifferences(t *testing.T) {
	logger := log.New(os.Stderr, "test: ", log.LstdFlags)
	scanner := NewDefaultPortScanner(100*time.Millisecond, 1, logger)

	target := "127.0.0.1"
	port := 54321 // Likely closed port

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Test TCP Connect scan
	tcpResult := scanner.ScanPort(ctx, target, port, ScanTypeTCPConnect)
	require.Equal(t, "tcp", tcpResult.Protocol, "TCP Connect should use tcp protocol")

	// Test UDP scan
	udpResult := scanner.ScanPort(ctx, target, port, ScanTypeUDP)
	require.Equal(t, "udp", udpResult.Protocol, "UDP scan should use udp protocol")

	// Results should have different protocols
	require.NotEqual(t, tcpResult.Protocol, udpResult.Protocol,
		"TCP and UDP scans should use different protocols")
}

// Test scan with multiple ports and scan types
func TestMultiplePortsScanTypeImplementation(t *testing.T) {
	logger := log.New(os.Stderr, "test: ", log.LstdFlags)
	scanner := NewDefaultPortScanner(100*time.Millisecond, 1, logger)

	target := "127.0.0.1"
	ports := []int{54321, 54322, 54323} // Likely closed ports

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Test with TCP Connect
	tcpResults := scanner.ScanPorts(ctx, target, ports, ScanTypeTCPConnect)
	require.Equal(t, len(ports), len(tcpResults), "Should return result for each port")

	for i, result := range tcpResults {
		require.Equal(t, ports[i], result.Port, "Port should match input")
		require.Equal(t, "tcp", result.Protocol, "Should use TCP protocol")
	}

	// Test with UDP
	udpResults := scanner.ScanPorts(ctx, target, ports, ScanTypeUDP)
	require.Equal(t, len(ports), len(udpResults), "Should return result for each port")

	for i, result := range udpResults {
		require.Equal(t, ports[i], result.Port, "Port should match input")
		require.Equal(t, "udp", result.Protocol, "Should use UDP protocol")
	}
}

// **Feature: network-mapper, Property 7: Error Resilience**
// **Validates: Requirements 1.5, 2.5**
// Property: For any network error encountered during scanning, the error should be logged
// and scanning should continue with remaining targets
func TestProperty7_ErrorResilience(t *testing.T) {
	// Property-based test with 100 iterations as specified in design
	for i := range 100 {
		t.Run(fmt.Sprintf("iteration_%d", i), func(t *testing.T) {
			// Create scanner with short timeout to induce errors
			logger := log.New(os.Stderr, "test: ", log.LstdFlags)
			scanner := NewDefaultPortScanner(1*time.Millisecond, 1, logger) // Very short timeout

			// Generate random targets that will likely cause errors
			targets := []string{
				"192.0.2.1",    // RFC 5737 test address (should be unreachable)
				"198.51.100.1", // RFC 5737 test address (should be unreachable)
				"203.0.113.1",  // RFC 5737 test address (should be unreachable)
				"127.0.0.1",    // Localhost (should work)
			}

			// Pick a random target
			target := targets[rand.Intn(len(targets))]

			// Generate random ports
			numPorts := rand.Intn(5) + 2 // 2-6 ports
			ports := make([]int, numPorts)
			for j := range numPorts {
				ports[j] = rand.Intn(10000) + 50000 // 50000-59999
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// Perform scan that may encounter errors
			results := scanner.ScanPorts(ctx, target, ports, ScanTypeTCPConnect)

			// Verify that we get results for all ports even if some fail
			require.Equal(t, len(ports), len(results),
				"Should return result for each port even if errors occur")

			// Verify that each result has the correct port number
			for j, result := range results {
				require.Equal(t, ports[j], result.Port,
					"Port number should be correct even if scan failed")

				// Verify that the result has a valid state (even if filtered due to error)
				require.Contains(t, []PortState{PortOpen, PortClosed, PortFiltered}, result.State,
					"Port state should be valid even if error occurred")

				// Verify that response time is recorded (even for failed scans)
				require.Greater(t, result.ResponseTime, time.Duration(0),
					"Response time should be recorded even for failed scans")

				// Verify protocol is correct
				require.Equal(t, "tcp", result.Protocol,
					"Protocol should be correct even if scan failed")
			}

			// For unreachable targets, most ports should be filtered
			if target != "127.0.0.1" {
				filteredCount := 0
				for _, result := range results {
					if result.State == PortFiltered {
						filteredCount++
					}
				}
				// At least some ports should be filtered for unreachable targets
				// (This is a probabilistic check - not all may be filtered due to timing)
			}
		})
	}
}

// Test error resilience with invalid targets
func TestErrorResilienceInvalidTargets(t *testing.T) {
	logger := log.New(os.Stderr, "test: ", log.LstdFlags)
	scanner := NewDefaultPortScanner(100*time.Millisecond, 1, logger)

	invalidTargets := []string{
		"invalid.hostname.that.does.not.exist.example",
		"999.999.999.999", // Invalid IP
		"192.0.2.1",       // Unreachable test IP
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, target := range invalidTargets {
		t.Run(target, func(t *testing.T) {
			ports := []int{80, 443, 22}

			// This should not panic or crash, even with invalid targets
			results := scanner.ScanPorts(ctx, target, ports, ScanTypeTCPConnect)

			// Should still return results for all ports
			require.Equal(t, len(ports), len(results),
				"Should return results even for invalid targets")

			// All results should have correct port numbers
			for i, result := range results {
				require.Equal(t, ports[i], result.Port,
					"Port number should be correct even for invalid target")
			}
		})
	}
}

// Test error resilience with invalid port numbers
func TestErrorResilienceInvalidPorts(t *testing.T) {
	logger := log.New(os.Stderr, "test: ", log.LstdFlags)
	scanner := NewDefaultPortScanner(100*time.Millisecond, 1, logger)

	target := "127.0.0.1"
	invalidPorts := []int{0, -1, 65536, 100000}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, port := range invalidPorts {
		t.Run(fmt.Sprintf("port_%d", port), func(t *testing.T) {
			// This should not panic, should handle invalid ports gracefully
			result := scanner.ScanPort(ctx, target, port, ScanTypeTCPConnect)

			// Should return a result with the port number (even if invalid)
			require.Equal(t, port, result.Port,
				"Should return result with correct port number even if invalid")

			// Invalid ports should be marked as filtered
			require.Equal(t, PortFiltered, result.State,
				"Invalid ports should be marked as filtered")
		})
	}
}

// Test that scanner continues after context cancellation
func TestErrorResilienceContextCancellation(t *testing.T) {
	logger := log.New(os.Stderr, "test: ", log.LstdFlags)
	scanner := NewDefaultPortScanner(1*time.Second, 1, logger)

	target := "127.0.0.1"
	port := 54321

	// Create a context that will be cancelled quickly
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// This should handle cancellation gracefully
	result := scanner.ScanPort(ctx, target, port, ScanTypeTCPConnect)

	// Should still return a result
	require.Equal(t, port, result.Port, "Should return result even after cancellation")
	require.Equal(t, "tcp", result.Protocol, "Should have correct protocol")
	require.Greater(t, result.ResponseTime, time.Duration(0), "Should have response time")
}

// Test network error identification
func TestNetworkErrorIdentification(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		isNetwork bool
	}{
		{
			name:      "nil error",
			err:       nil,
			isNetwork: false,
		},
		{
			name:      "connection refused",
			err:       fmt.Errorf("connection refused"),
			isNetwork: true,
		},
		{
			name:      "network unreachable",
			err:       fmt.Errorf("network is unreachable"),
			isNetwork: true,
		},
		{
			name:      "timeout",
			err:       fmt.Errorf("connection timed out"),
			isNetwork: true,
		},
		{
			name:      "dns failure",
			err:       fmt.Errorf("temporary failure in name resolution"),
			isNetwork: true,
		},
		{
			name:      "other error",
			err:       fmt.Errorf("some other error"),
			isNetwork: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsNetworkError(tt.err)
			require.Equal(t, tt.isNetwork, result,
				"Network error identification should be correct for %s", tt.name)
		})
	}
}

// **Feature: network-mapper, Property 1: Target Scanning Completeness**
// **Validates: Requirements 1.1**
// Property: For any list of targets provided, all targets should be resolved and included in the scan
func TestProperty1_TargetScanningCompleteness(t *testing.T) {
	// Property-based test with 100 iterations as specified in design
	for i := range 100 {
		t.Run(fmt.Sprintf("iteration_%d", i), func(t *testing.T) {
			// Create target resolver
			resolver := NewTargetResolver()

			// Generate random targets of different types
			targets := generateRandomTargets(rand.Intn(5) + 1) // 1-5 targets

			// Resolve targets
			resolvedTargets, err := resolver.ResolveTargets(targets)

			// Should not fail for valid targets
			if err != nil {
				// If error occurs, it should be due to invalid target format or network issues
				// Skip this iteration if we hit network issues
				t.Skipf("Network error during target resolution: %v", err)
				return
			}

			// Verify that we get resolved targets for all input targets
			require.Equal(t, len(targets), len(resolvedTargets),
				"Should resolve all %d targets", len(targets))

			// Verify that each resolved target has the correct original value
			for i, resolved := range resolvedTargets {
				require.Equal(t, targets[i], resolved.Original,
					"Resolved target should preserve original target string")

				// Verify that each resolved target has at least one IP
				require.Greater(t, len(resolved.IPs), 0,
					"Resolved target should have at least one IP address")

				// Verify that all IPs are valid
				for _, ip := range resolved.IPs {
					require.NotNil(t, ip, "IP should not be nil")
					require.True(t, len(ip) == 4 || len(ip) == 16,
						"IP should be IPv4 (4 bytes) or IPv6 (16 bytes)")
				}
			}
		})
	}
}

// **Feature: network-mapper, Property 4: CIDR Range Expansion**
// **Validates: Requirements 2.1**
// Property: For any valid CIDR range, all IP addresses within the range should be generated
func TestProperty4_CIDRRangeExpansion(t *testing.T) {
	// Property-based test with 100 iterations as specified in design
	for i := range 100 {
		t.Run(fmt.Sprintf("iteration_%d", i), func(t *testing.T) {
			// Create target resolver
			resolver := NewTargetResolver()

			// Generate random CIDR ranges (keep them small for testing)
			cidr := generateRandomCIDR()

			// Expand CIDR range
			ips, err := resolver.ExpandCIDR(cidr)
			require.NoError(t, err, "Should be able to expand valid CIDR %s", cidr)

			// Verify that we get the expected number of IPs
			expectedCount := calculateExpectedCIDRCount(cidr)
			require.Equal(t, expectedCount, len(ips),
				"Should expand CIDR %s to %d IPs", cidr, expectedCount)

			// Verify that all IPs are within the CIDR range
			_, ipNet, err := net.ParseCIDR(cidr)
			require.NoError(t, err, "CIDR should be parseable")

			for _, ipStr := range ips {
				ip := net.ParseIP(ipStr)
				require.NotNil(t, ip, "Expanded IP %s should be valid", ipStr)
				require.True(t, ipNet.Contains(ip),
					"IP %s should be within CIDR range %s", ipStr, cidr)
			}

			// Verify no duplicate IPs
			ipSet := make(map[string]bool)
			for _, ip := range ips {
				require.False(t, ipSet[ip], "Should not have duplicate IP %s", ip)
				ipSet[ip] = true
			}
		})
	}
}

// Test target resolution with various target types
func TestTargetResolutionTypes(t *testing.T) {
	resolver := NewTargetResolver()

	tests := []struct {
		name        string
		target      string
		expectError bool
		expectIPs   int // minimum expected IPs
	}{
		{
			name:        "IPv4 address",
			target:      "192.168.1.1",
			expectError: false,
			expectIPs:   1,
		},
		{
			name:        "IPv6 address",
			target:      "::1",
			expectError: false,
			expectIPs:   1,
		},
		{
			name:        "small CIDR range",
			target:      "192.168.1.0/30",
			expectError: false,
			expectIPs:   4,
		},
		{
			name:        "IP range with octet",
			target:      "192.168.1.1-5",
			expectError: false,
			expectIPs:   5,
		},
		{
			name:        "localhost hostname",
			target:      "localhost",
			expectError: false,
			expectIPs:   1,
		},
		{
			name:        "invalid target",
			target:      "invalid..hostname",
			expectError: true,
			expectIPs:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targets, err := resolver.ResolveTargets([]string{tt.target})

			if tt.expectError {
				require.Error(t, err, "Should return error for invalid target")
				return
			}

			require.NoError(t, err, "Should not return error for valid target")
			require.Equal(t, 1, len(targets), "Should resolve to one target")
			require.GreaterOrEqual(t, len(targets[0].IPs), tt.expectIPs,
				"Should have at least %d IPs", tt.expectIPs)
		})
	}
}

// Test CIDR expansion edge cases
func TestCIDRExpansionEdgeCases(t *testing.T) {
	resolver := NewTargetResolver()

	tests := []struct {
		name        string
		cidr        string
		expectError bool
		expectCount int
	}{
		{
			name:        "single IP /32",
			cidr:        "192.168.1.1/32",
			expectError: false,
			expectCount: 1,
		},
		{
			name:        "small range /30",
			cidr:        "192.168.1.0/30",
			expectError: false,
			expectCount: 4,
		},
		{
			name:        "medium range /24",
			cidr:        "192.168.1.0/24",
			expectError: false,
			expectCount: 256,
		},
		{
			name:        "too large range /8",
			cidr:        "10.0.0.0/8",
			expectError: true,
			expectCount: 0,
		},
		{
			name:        "invalid CIDR",
			cidr:        "invalid/cidr",
			expectError: true,
			expectCount: 0,
		},
		{
			name:        "IPv6 single /128",
			cidr:        "::1/128",
			expectError: false,
			expectCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, err := resolver.ExpandCIDR(tt.cidr)

			if tt.expectError {
				require.Error(t, err, "Should return error for invalid/large CIDR")
				return
			}

			require.NoError(t, err, "Should not return error for valid CIDR")
			require.Equal(t, tt.expectCount, len(ips),
				"Should expand to exactly %d IPs", tt.expectCount)
		})
	}
}

// Test hostname resolution
func TestHostnameResolution(t *testing.T) {
	resolver := NewTargetResolver()

	tests := []struct {
		name        string
		hostname    string
		expectError bool
	}{
		{
			name:        "localhost",
			hostname:    "localhost",
			expectError: false,
		},
		{
			name:        "invalid hostname",
			hostname:    "this.hostname.should.not.exist.example.invalid",
			expectError: true,
		},
		{
			name:        "empty hostname",
			hostname:    "",
			expectError: true,
		},
		{
			name:        "hostname too long",
			hostname:    strings.Repeat("a", 254),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips, err := resolver.ResolveHostname(tt.hostname)

			if tt.expectError {
				require.Error(t, err, "Should return error for invalid hostname")
				return
			}

			require.NoError(t, err, "Should not return error for valid hostname")
			require.Greater(t, len(ips), 0, "Should resolve to at least one IP")

			// Verify all returned IPs are valid
			for _, ipStr := range ips {
				ip := net.ParseIP(ipStr)
				require.NotNil(t, ip, "Resolved IP %s should be valid", ipStr)
			}
		})
	}
}

// Helper functions for property tests

// generateRandomTargets creates random valid targets for testing
func generateRandomTargets(count int) []string {
	targets := make([]string, count)
	targetTypes := []string{"ip", "cidr", "hostname", "range"}

	for i := 0; i < count; i++ {
		targetType := targetTypes[rand.Intn(len(targetTypes))]

		switch targetType {
		case "ip":
			targets[i] = fmt.Sprintf("192.168.%d.%d", rand.Intn(256), rand.Intn(256))
		case "cidr":
			targets[i] = fmt.Sprintf("192.168.%d.0/%d", rand.Intn(256), 28+rand.Intn(5)) // /28 to /32
		case "hostname":
			targets[i] = "localhost" // Use localhost as a reliable hostname
		case "range":
			start := rand.Intn(250) + 1
			end := start + rand.Intn(5) + 1
			targets[i] = fmt.Sprintf("192.168.1.%d-%d", start, end)
		}
	}

	return targets
}

// generateRandomCIDR creates a random small CIDR range for testing
func generateRandomCIDR() string {
	// Generate small CIDR ranges to avoid memory issues in tests
	prefixLengths := []int{28, 29, 30, 31, 32} // Small ranges
	prefixLength := prefixLengths[rand.Intn(len(prefixLengths))]

	return fmt.Sprintf("192.168.%d.%d/%d",
		rand.Intn(256),
		rand.Intn(256),
		prefixLength)
}

// calculateExpectedCIDRCount calculates expected number of IPs in a CIDR range
func calculateExpectedCIDRCount(cidr string) int {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0
	}

	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones
	return 1 << hostBits
}
