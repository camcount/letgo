package networkmapper

import (
	"strings"
	"testing"
	"time"
)

// TestEnhancedResultDisplay verifies that enhanced data is properly displayed in all output formats
func TestEnhancedResultDisplay(t *testing.T) {
	// Create a comprehensive test result with all enhanced data
	resolvedIPs := []ResolvedIP{
		{
			IP:         "192.168.1.100",
			Type:       "IPv4",
			Hostname:   "test.example.com",
			ResolvedAt: time.Now(),
		},
		{
			IP:         "2001:db8::1",
			Type:       "IPv6",
			Hostname:   "test.example.com",
			ResolvedAt: time.Now(),
		},
	}

	protection := []ProtectionService{
		{
			Type:       ProtectionCDN,
			Name:       "Cloudflare",
			Confidence: 95.0,
			Evidence:   []string{"cf-ray header", "server: cloudflare"},
			Details:    []KeyValue{{Key: "detection_method", Value: "http_headers"}},
		},
	}

	infrastructure := InfrastructureInfo{
		HostingProvider: "Amazon Web Services",
		CloudPlatform:   "AWS",
		DataCenter:      "us-east-1, Virginia, US",
		NetworkInfo: NetworkInfo{
			ASN:          "AS16509",
			Organization: "Amazon.com, Inc.",
		},
		SSLInfo: SSLCertInfo{
			Issuer:    "Let's Encrypt Authority X3",
			Subject:   "CN=test.example.com",
			ValidFrom: time.Now().AddDate(0, -1, 0),
			ValidTo:   time.Now().AddDate(1, 0, 0),
			SANs:      []string{"test.example.com", "www.test.example.com"},
		},
		Subdomains: []string{"api.test.example.com", "cdn.test.example.com"},
	}

	hostResult := HostResult{
		Target:         "test.example.com",
		ResolvedIPs:    resolvedIPs,
		Status:         HostUp,
		Ports:          []PortResult{},
		Protection:     protection,
		Infrastructure: infrastructure,
		ResponseTime:   50 * time.Millisecond,
	}

	scanResult := &ScanResult{
		Timestamp: time.Now(),
		ScanConfig: ScanConfig{
			Targets: []string{"test.example.com"},
		},
		Hosts: []HostResult{hostResult},
	}

	rm := NewResultManager()

	// Test text format
	textOutput, err := rm.ExportResults(scanResult, OutputFormatText)
	if err != nil {
		t.Fatalf("Failed to export text format: %v", err)
	}

	textStr := string(textOutput)

	// Verify hostname and IP display completeness (Requirements 10.3)
	if !strings.Contains(textStr, "test.example.com") {
		t.Error("Text output should contain original hostname")
	}
	if !strings.Contains(textStr, "192.168.1.100") {
		t.Error("Text output should contain IPv4 address")
	}
	if !strings.Contains(textStr, "2001:db8::1") {
		t.Error("Text output should contain IPv6 address")
	}
	if !strings.Contains(textStr, "Resolved IPs:") {
		t.Error("Text output should contain 'Resolved IPs:' section")
	}

	// Verify protection service information (Requirements 11.2)
	if !strings.Contains(textStr, "Protection Services:") {
		t.Error("Text output should contain 'Protection Services:' section")
	}
	if !strings.Contains(textStr, "Cloudflare") {
		t.Error("Text output should contain protection service name")
	}
	if !strings.Contains(textStr, "95.0% confidence") {
		t.Error("Text output should contain confidence level")
	}

	// Verify infrastructure information (Requirements 12.2, 12.3)
	if !strings.Contains(textStr, "Infrastructure:") {
		t.Error("Text output should contain 'Infrastructure:' section")
	}
	if !strings.Contains(textStr, "Amazon Web Services") {
		t.Error("Text output should contain hosting provider")
	}
	if !strings.Contains(textStr, "AWS") {
		t.Error("Text output should contain cloud platform")
	}
	if !strings.Contains(textStr, "AS16509") {
		t.Error("Text output should contain ASN information")
	}

	// Verify SSL certificate information (Requirements 12.4)
	if !strings.Contains(textStr, "SSL Certificate:") {
		t.Error("Text output should contain 'SSL Certificate:' section")
	}
	if !strings.Contains(textStr, "Let's Encrypt Authority X3") {
		t.Error("Text output should contain certificate issuer")
	}

	// Verify subdomain information (Requirements 12.5)
	if !strings.Contains(textStr, "Subdomains:") {
		t.Error("Text output should contain 'Subdomains:' section")
	}
	if !strings.Contains(textStr, "api.test.example.com") {
		t.Error("Text output should contain discovered subdomains")
	}

	// Test JSON format
	jsonOutput, err := rm.ExportResults(scanResult, OutputFormatJSON)
	if err != nil {
		t.Fatalf("Failed to export JSON format: %v", err)
	}

	jsonStr := string(jsonOutput)

	// Verify JSON contains enhanced data
	if !strings.Contains(jsonStr, "resolved_ips") {
		t.Error("JSON output should contain 'resolved_ips' field")
	}
	if !strings.Contains(jsonStr, "protection") {
		t.Error("JSON output should contain 'protection' field")
	}
	if !strings.Contains(jsonStr, "infrastructure") {
		t.Error("JSON output should contain 'infrastructure' field")
	}
	if !strings.Contains(jsonStr, "hosting_provider") {
		t.Error("JSON output should contain 'hosting_provider' field")
	}

	// Test XML format
	xmlOutput, err := rm.ExportResults(scanResult, OutputFormatXML)
	if err != nil {
		t.Fatalf("Failed to export XML format: %v", err)
	}

	xmlStr := string(xmlOutput)

	// Verify XML contains enhanced data
	if !strings.Contains(xmlStr, "test.example.com") {
		t.Error("XML output should contain hostname")
	}
	if !strings.Contains(xmlStr, "192.168.1.100") {
		t.Error("XML output should contain IP addresses")
	}
}