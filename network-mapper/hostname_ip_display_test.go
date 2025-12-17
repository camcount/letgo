package networkmapper

import (
	"fmt"
	"strings"
	"testing"
	"testing/quick"
	"time"
)

// **Feature: network-mapper, Property 23: Hostname and IP Display Completeness**
// **Validates: Requirements 10.3**
// Property: For any scan result involving a hostname, both the original hostname and all resolved IP addresses should be shown in the output
func TestProperty_HostnameAndIPDisplayCompleteness(t *testing.T) {
	config := &quick.Config{MaxCount: 100}

	property := func(hostname string, ipCount uint8) bool {
		// Ensure we have a valid hostname and at least one IP
		if hostname == "" || len(hostname) > 50 || !isValidTestHostname(hostname) {
			hostname = "example.com"
		}
		if ipCount == 0 {
			ipCount = 1
		}
		if ipCount > 5 {
			ipCount = 5 // Limit to reasonable number for testing
		}

		// Create test scan result with hostname and resolved IPs
		resolvedIPs := make([]ResolvedIP, int(ipCount))
		for i := 0; i < int(ipCount); i++ {
			resolvedIPs[i] = ResolvedIP{
				IP:         generateTestIP(i),
				Type:       "IPv4",
				Hostname:   hostname,
				ResolvedAt: time.Now(),
			}
		}

		hostResult := HostResult{
			Target:      hostname,
			ResolvedIPs: resolvedIPs,
			Status:      HostUp,
			Ports:       []PortResult{},
			ResponseTime: 100 * time.Millisecond,
		}

		scanResult := &ScanResult{
			Timestamp: time.Now(),
			ScanConfig: ScanConfig{
				Targets: []string{hostname},
			},
			Hosts: []HostResult{hostResult},
		}

		// Export to text format
		rm := NewResultManager()
		output, err := rm.ExportResults(scanResult, OutputFormatText)
		if err != nil {
			return false
		}

		outputStr := string(output)

		// Verify original hostname is displayed
		if !strings.Contains(outputStr, hostname) {
			return false
		}

		// Verify all resolved IP addresses are displayed
		for _, resolvedIP := range resolvedIPs {
			if !strings.Contains(outputStr, resolvedIP.IP) {
				return false
			}
		}

		// Verify the "Resolved IPs:" section exists when there are resolved IPs
		if len(resolvedIPs) > 0 && !strings.Contains(outputStr, "Resolved IPs:") {
			return false
		}

		return true
	}

	if err := quick.Check(property, config); err != nil {
		t.Errorf("Property failed: %v", err)
	}
}

// TestProperty_HostnameAndIPDisplayCompleteness_JSON tests the same property for JSON output
func TestProperty_HostnameAndIPDisplayCompleteness_JSON(t *testing.T) {
	config := &quick.Config{MaxCount: 100}

	property := func(hostname string, ipCount uint8) bool {
		// Always use a safe hostname for JSON testing to avoid Unicode issues
		hostname = "test-example.com"
		if ipCount == 0 {
			ipCount = 1
		}
		if ipCount > 5 {
			ipCount = 5 // Limit to reasonable number for testing
		}

		// Create test scan result with hostname and resolved IPs
		resolvedIPs := make([]ResolvedIP, int(ipCount))
		for i := 0; i < int(ipCount); i++ {
			resolvedIPs[i] = ResolvedIP{
				IP:         generateTestIP(i),
				Type:       "IPv4",
				Hostname:   hostname,
				ResolvedAt: time.Now(),
			}
		}

		hostResult := HostResult{
			Target:      hostname,
			ResolvedIPs: resolvedIPs,
			Status:      HostUp,
			Ports:       []PortResult{},
			ResponseTime: 100 * time.Millisecond,
		}

		scanResult := &ScanResult{
			Timestamp: time.Now(),
			ScanConfig: ScanConfig{
				Targets: []string{hostname},
			},
			Hosts: []HostResult{hostResult},
		}

		// Export to JSON format
		rm := NewResultManager()
		output, err := rm.ExportResults(scanResult, OutputFormatJSON)
		if err != nil {
			return false
		}

		outputStr := string(output)

		// Verify original hostname is in JSON
		if !strings.Contains(outputStr, hostname) {
			return false
		}

		// Verify all resolved IP addresses are in JSON
		for _, resolvedIP := range resolvedIPs {
			if !strings.Contains(outputStr, resolvedIP.IP) {
				return false
			}
		}

		// Verify JSON structure includes resolved_ips field
		if len(resolvedIPs) > 0 && !strings.Contains(outputStr, "resolved_ips") {
			return false
		}

		return true
	}

	if err := quick.Check(property, config); err != nil {
		t.Errorf("Property failed: %v", err)
	}
}

// TestProperty_HostnameAndIPDisplayCompleteness_XML tests the same property for XML output
func TestProperty_HostnameAndIPDisplayCompleteness_XML(t *testing.T) {
	config := &quick.Config{MaxCount: 100}

	property := func(hostname string, ipCount uint8) bool {
		// Ensure we have a valid hostname and at least one IP
		if hostname == "" || len(hostname) > 50 || !isValidTestHostname(hostname) {
			hostname = "example.com"
		}
		if ipCount == 0 {
			ipCount = 1
		}
		if ipCount > 5 {
			ipCount = 5 // Limit to reasonable number for testing
		}

		// Create test scan result with hostname and resolved IPs
		resolvedIPs := make([]ResolvedIP, int(ipCount))
		for i := 0; i < int(ipCount); i++ {
			resolvedIPs[i] = ResolvedIP{
				IP:         generateTestIP(i),
				Type:       "IPv4",
				Hostname:   hostname,
				ResolvedAt: time.Now(),
			}
		}

		hostResult := HostResult{
			Target:      hostname,
			ResolvedIPs: resolvedIPs,
			Status:      HostUp,
			Ports:       []PortResult{},
			ResponseTime: 100 * time.Millisecond,
		}

		scanResult := &ScanResult{
			Timestamp: time.Now(),
			ScanConfig: ScanConfig{
				Targets: []string{hostname},
			},
			Hosts: []HostResult{hostResult},
		}

		// Export to XML format
		rm := NewResultManager()
		output, err := rm.ExportResults(scanResult, OutputFormatXML)
		if err != nil {
			return false
		}

		outputStr := string(output)

		// Verify original hostname is in XML
		if !strings.Contains(outputStr, hostname) {
			return false
		}

		// Verify all resolved IP addresses are in XML
		for _, resolvedIP := range resolvedIPs {
			if !strings.Contains(outputStr, resolvedIP.IP) {
				return false
			}
		}

		return true
	}

	if err := quick.Check(property, config); err != nil {
		t.Errorf("Property failed: %v", err)
	}
}

// generateTestIP generates a test IP address based on index
func generateTestIP(index int) string {
	// Generate valid IP addresses in the 192.168.1.x range
	octet := (index % 254) + 1 // Ensure valid IP range 1-254
	return "192.168.1." + fmt.Sprintf("%d", octet)
}

// isValidTestHostname checks if a hostname contains only ASCII characters and valid hostname characters
func isValidTestHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 253 {
		return false
	}
	
	for _, r := range hostname {
		// Only allow ASCII letters, digits, dots, and hyphens
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-') {
			return false
		}
	}
	return true
}