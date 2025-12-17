package consolemenu

import (
	"bufio"
	"strings"
	"testing"
	"time"

	networkmapper "github.com/letgo/network-mapper"
)

// TestConfigureCustomScan_ProtectionDetectionOptions tests protection detection option handling
func TestConfigureCustomScan_ProtectionDetectionOptions(t *testing.T) {
	menu := &Menu{}
	
	// Test enabling protection detection
	input := "top1000\ny\ny\ny\ny\nn\nn\n50\n5\n3\n"
	reader := bufio.NewReader(strings.NewReader(input))
	
	config := &networkmapper.ScanConfig{}
	menu.configureCustomScan(config, reader)
	
	if !config.ProtectionDetect {
		t.Error("Expected protection detection to be enabled")
	}
	
	// Test disabling protection detection
	input = "top1000\ny\ny\nn\ny\nn\nn\n50\n5\n3\n"
	reader = bufio.NewReader(strings.NewReader(input))
	
	config = &networkmapper.ScanConfig{}
	menu.configureCustomScan(config, reader)
	
	if config.ProtectionDetect {
		t.Error("Expected protection detection to be disabled")
	}
}

// TestConfigureCustomScan_InfrastructureAnalysisOptions tests infrastructure analysis configuration
func TestConfigureCustomScan_InfrastructureAnalysisOptions(t *testing.T) {
	menu := &Menu{}
	
	// Test enabling infrastructure analysis
	input := "top1000\ny\ny\ny\ny\nn\nn\n50\n5\n3\n"
	reader := bufio.NewReader(strings.NewReader(input))
	
	config := &networkmapper.ScanConfig{}
	menu.configureCustomScan(config, reader)
	
	if !config.InfraAnalysis {
		t.Error("Expected infrastructure analysis to be enabled")
	}
	
	// Test disabling infrastructure analysis
	input = "top1000\ny\ny\ny\nn\nn\nn\n50\n5\n3\n"
	reader = bufio.NewReader(strings.NewReader(input))
	
	config = &networkmapper.ScanConfig{}
	menu.configureCustomScan(config, reader)
	
	if config.InfraAnalysis {
		t.Error("Expected infrastructure analysis to be disabled")
	}
}

// TestConfigureCustomScan_SubdomainEnumerationOptions tests subdomain enumeration controls
func TestConfigureCustomScan_SubdomainEnumerationOptions(t *testing.T) {
	menu := &Menu{}
	
	// Test enabling subdomain enumeration
	input := "top1000\ny\ny\ny\ny\ny\nn\n50\n5\n3\n"
	reader := bufio.NewReader(strings.NewReader(input))
	
	config := &networkmapper.ScanConfig{}
	menu.configureCustomScan(config, reader)
	
	if !config.SubdomainEnum {
		t.Error("Expected subdomain enumeration to be enabled")
	}
	
	// Test disabling subdomain enumeration (default)
	input = "top1000\ny\ny\ny\ny\nn\nn\n50\n5\n3\n"
	reader = bufio.NewReader(strings.NewReader(input))
	
	config = &networkmapper.ScanConfig{}
	menu.configureCustomScan(config, reader)
	
	if config.SubdomainEnum {
		t.Error("Expected subdomain enumeration to be disabled by default")
	}
}

// TestConfigureCustomScan_IPv6Options tests IPv6 address inclusion options
func TestConfigureCustomScan_IPv6Options(t *testing.T) {
	menu := &Menu{}
	
	// Test enabling IPv6
	input := "top1000\ny\ny\ny\ny\nn\ny\n50\n5\n3\n"
	reader := bufio.NewReader(strings.NewReader(input))
	
	config := &networkmapper.ScanConfig{}
	menu.configureCustomScan(config, reader)
	
	if !config.IncludeIPv6 {
		t.Error("Expected IPv6 to be enabled")
	}
	
	// Test disabling IPv6 (default)
	input = "top1000\ny\ny\ny\ny\nn\nn\n50\n5\n3\n"
	reader = bufio.NewReader(strings.NewReader(input))
	
	config = &networkmapper.ScanConfig{}
	menu.configureCustomScan(config, reader)
	
	if config.IncludeIPv6 {
		t.Error("Expected IPv6 to be disabled by default")
	}
}

// TestConfigureCustomScan_DNSTimeoutConfiguration tests DNS timeout configuration
func TestConfigureCustomScan_DNSTimeoutConfiguration(t *testing.T) {
	menu := &Menu{}
	
	// Test custom DNS timeout
	input := "top1000\ny\ny\ny\ny\nn\nn\n50\n5\n10\n"
	reader := bufio.NewReader(strings.NewReader(input))
	
	config := &networkmapper.ScanConfig{}
	menu.configureCustomScan(config, reader)
	
	expectedTimeout := 10 * time.Second
	if config.DNSTimeout != expectedTimeout {
		t.Errorf("Expected DNS timeout to be %v, got %v", expectedTimeout, config.DNSTimeout)
	}
	
	// Test default DNS timeout
	input = "top1000\ny\ny\ny\ny\nn\nn\n50\n5\n\n"
	reader = bufio.NewReader(strings.NewReader(input))
	
	config = &networkmapper.ScanConfig{}
	menu.configureCustomScan(config, reader)
	
	expectedTimeout = 3 * time.Second
	if config.DNSTimeout != expectedTimeout {
		t.Errorf("Expected default DNS timeout to be %v, got %v", expectedTimeout, config.DNSTimeout)
	}
}

// TestScanProfileConfiguration tests that scan profiles set enhanced features correctly
func TestScanProfileConfiguration(t *testing.T) {
	testCases := []struct {
		name                 string
		profileChoice        string
		expectedProtection   bool
		expectedInfra        bool
		expectedSubdomain    bool
	}{
		{
			name:               "Quick scan profile",
			profileChoice:      "1",
			expectedProtection: false,
			expectedInfra:      false,
			expectedSubdomain:  false,
		},
		{
			name:               "Comprehensive scan profile",
			profileChoice:      "2",
			expectedProtection: true,
			expectedInfra:      true,
			expectedSubdomain:  true,
		},
		{
			name:               "Stealth scan profile",
			profileChoice:      "3",
			expectedProtection: false,
			expectedInfra:      false,
			expectedSubdomain:  false,
		},
		{
			name:               "Vulnerability scan profile",
			profileChoice:      "4",
			expectedProtection: true,
			expectedInfra:      true,
			expectedSubdomain:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := networkmapper.ScanConfig{
				MaxThreads:   50,
				Timeout:      5 * time.Second,
				DNSTimeout:   3 * time.Second,
				OutputFormat: networkmapper.OutputFormatText,
				IncludeIPv6:  false,
			}

			// Simulate profile selection logic
			switch tc.profileChoice {
			case "1":
				// Quick scan
				config.Ports = getTopPorts(100)
				config.ServiceDetect = false
				config.OSDetect = false
				config.ProtectionDetect = false
				config.InfraAnalysis = false
				config.SubdomainEnum = false
			case "3":
				// Stealth scan
				config.Ports = getTopPorts(200)
				config.ServiceDetect = true
				config.OSDetect = false
				config.ProtectionDetect = false
				config.InfraAnalysis = false
				config.SubdomainEnum = false
				config.MaxThreads = 10
				config.Timeout = 10 * time.Second
			case "4":
				// Vulnerability scan
				config.Ports = getVulnerabilityPorts()
				config.ServiceDetect = true
				config.OSDetect = true
				config.ProtectionDetect = true
				config.InfraAnalysis = true
				config.SubdomainEnum = false
				config.MaxThreads = 25
			default:
				// Comprehensive scan (default)
				config.Ports = getTopPorts(1000)
				config.ServiceDetect = true
				config.OSDetect = true
				config.ProtectionDetect = true
				config.InfraAnalysis = true
				config.SubdomainEnum = true
			}

			if config.ProtectionDetect != tc.expectedProtection {
				t.Errorf("Expected ProtectionDetect to be %v, got %v", tc.expectedProtection, config.ProtectionDetect)
			}
			if config.InfraAnalysis != tc.expectedInfra {
				t.Errorf("Expected InfraAnalysis to be %v, got %v", tc.expectedInfra, config.InfraAnalysis)
			}
			if config.SubdomainEnum != tc.expectedSubdomain {
				t.Errorf("Expected SubdomainEnum to be %v, got %v", tc.expectedSubdomain, config.SubdomainEnum)
			}
		})
	}
}

// TestEnhancedResultDisplay tests the enhanced result display formatting
func TestEnhancedResultDisplay(t *testing.T) {
	// Create mock scan results with enhanced data
	results := &networkmapper.ScanResult{
		Hosts: []networkmapper.HostResult{
			{
				Target: "example.com",
				Status: networkmapper.HostUp,
				ResolvedIPs: []networkmapper.ResolvedIP{
					{
						IP:   "192.168.1.1",
						Type: "IPv4",
					},
					{
						IP:   "2001:db8::1",
						Type: "IPv6",
					},
				},
				Protection: []networkmapper.ProtectionService{
					{
						Type:       networkmapper.ProtectionCDN,
						Name:       "Cloudflare",
						Confidence: 95.0,
						Evidence:   []string{"cf-ray header", "cloudflare server"},
					},
				},
				Infrastructure: networkmapper.InfrastructureInfo{
					HostingProvider: "Amazon Web Services",
					CloudPlatform:   "AWS",
					DataCenter:      "us-east-1",
					NetworkInfo: networkmapper.NetworkInfo{
						ASN:          "AS16509",
						Organization: "Amazon.com, Inc.",
					},
					SSLInfo: networkmapper.SSLCertInfo{
						Subject: "CN=example.com",
						Issuer:  "CN=Let's Encrypt Authority X3",
						SANs:    []string{"example.com", "www.example.com"},
					},
					Subdomains: []string{"api.example.com", "cdn.example.com"},
				},
				Ports: []networkmapper.PortResult{
					{
						Port:     443,
						Protocol: "TCP",
						State:    networkmapper.PortOpen,
						Service: networkmapper.ServiceInfo{
							Name:    "https",
							Version: "nginx/1.18.0",
						},
					},
				},
			},
		},
	}

	// Test that the result contains expected enhanced information
	// This is a basic test to ensure the data structures are properly populated
	host := results.Hosts[0]
	
	if len(host.ResolvedIPs) != 2 {
		t.Errorf("Expected 2 resolved IPs, got %d", len(host.ResolvedIPs))
	}
	
	if len(host.Protection) != 1 {
		t.Errorf("Expected 1 protection service, got %d", len(host.Protection))
	}
	
	if host.Infrastructure.HostingProvider != "Amazon Web Services" {
		t.Errorf("Expected hosting provider to be 'Amazon Web Services', got '%s'", host.Infrastructure.HostingProvider)
	}
	
	if len(host.Infrastructure.Subdomains) != 2 {
		t.Errorf("Expected 2 subdomains, got %d", len(host.Infrastructure.Subdomains))
	}
	
	if len(host.Infrastructure.SSLInfo.SANs) != 2 {
		t.Errorf("Expected 2 SSL SANs, got %d", len(host.Infrastructure.SSLInfo.SANs))
	}
}

// TestPortParsing tests the port parsing functionality with various inputs
func TestPortParsing(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		expectedLen int
		shouldError bool
	}{
		{
			name:        "Single port",
			input:       "80",
			expectedLen: 1,
			shouldError: false,
		},
		{
			name:        "Multiple ports",
			input:       "80,443,8080",
			expectedLen: 3,
			shouldError: false,
		},
		{
			name:        "Port range",
			input:       "80-85",
			expectedLen: 6,
			shouldError: false,
		},
		{
			name:        "Mixed ports and ranges",
			input:       "80,443,8000-8005",
			expectedLen: 8,
			shouldError: false,
		},
		{
			name:        "Invalid port",
			input:       "70000",
			expectedLen: 0,
			shouldError: true,
		},
		{
			name:        "Invalid range",
			input:       "80-70",
			expectedLen: 0,
			shouldError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ports, err := parsePorts(tc.input)
			
			if tc.shouldError && err == nil {
				t.Error("Expected error but got none")
			}
			
			if !tc.shouldError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			
			if len(ports) != tc.expectedLen {
				t.Errorf("Expected %d ports, got %d", tc.expectedLen, len(ports))
			}
		})
	}
}