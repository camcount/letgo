package networkmapper

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestExportWebServicesForScanning tests the web services export functionality
func TestExportWebServicesForScanning(t *testing.T) {
	// Create test results with web services
	results := &ScanResult{
		Timestamp: time.Now(),
		Hosts: []HostResult{
			{
				Target: "192.168.1.1",
				Status: HostUp,
				Ports: []PortResult{
					{
						Port:     80,
						Protocol: "TCP",
						State:    PortOpen,
						Service: ServiceInfo{
							Name: "http",
						},
					},
					{
						Port:     443,
						Protocol: "TCP",
						State:    PortOpen,
						Service: ServiceInfo{
							Name: "https",
						},
					},
					{
						Port:     22,
						Protocol: "TCP",
						State:    PortOpen,
						Service: ServiceInfo{
							Name: "ssh",
						},
					},
				},
			},
			{
				Target: "192.168.1.2",
				Status: HostUp,
				Ports: []PortResult{
					{
						Port:     8080,
						Protocol: "TCP",
						State:    PortOpen,
						Service: ServiceInfo{
							Name: "http-proxy",
						},
					},
				},
			},
		},
	}

	// Create temporary output file
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "web-services.txt")

	// Test export
	resultManager := NewResultManager()
	err := resultManager.ExportWebServicesForScanning(results, outputPath)
	if err != nil {
		t.Fatalf("Failed to export web services: %v", err)
	}

	// Read and verify output
	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	contentStr := string(content)

	// Should contain web service URLs
	expectedURLs := []string{
		"http://192.168.1.1",
		"https://192.168.1.1",
		"http://192.168.1.2:8080",
	}

	for _, expectedURL := range expectedURLs {
		if !strings.Contains(contentStr, expectedURL) {
			t.Errorf("Expected URL %s not found in output", expectedURL)
		}
	}

	// Should not contain SSH service
	if strings.Contains(contentStr, "ssh") {
		t.Error("SSH service should not be included in web services export")
	}
}

// TestExportTargetsForBruteForce tests the authentication services export functionality
func TestExportTargetsForBruteForce(t *testing.T) {
	// Create test results with authentication services
	results := &ScanResult{
		Timestamp: time.Now(),
		Hosts: []HostResult{
			{
				Target: "192.168.1.1",
				Status: HostUp,
				Ports: []PortResult{
					{
						Port:     22,
						Protocol: "TCP",
						State:    PortOpen,
						Service: ServiceInfo{
							Name: "ssh",
						},
						Banner: "SSH-2.0-OpenSSH_8.0",
					},
					{
						Port:     21,
						Protocol: "TCP",
						State:    PortOpen,
						Service: ServiceInfo{
							Name: "ftp",
						},
						Banner: "220 FTP Server ready",
					},
					{
						Port:     80,
						Protocol: "TCP",
						State:    PortOpen,
						Service: ServiceInfo{
							Name: "http",
						},
					},
				},
			},
		},
	}

	// Create temporary output file
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "auth-services.txt")

	// Test export
	resultManager := NewResultManager()
	err := resultManager.ExportTargetsForBruteForce(results, outputPath)
	if err != nil {
		t.Fatalf("Failed to export authentication services: %v", err)
	}

	// Read and verify output
	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	contentStr := string(content)

	// Should contain authentication services
	expectedServices := []string{
		"192.168.1.1:22|ssh|TCP|SSH-2.0-OpenSSH_8.0",
		"192.168.1.1:21|ftp|TCP|220 FTP Server ready",
		"192.168.1.1:80|http|TCP|",
	}

	for _, expectedService := range expectedServices {
		if !strings.Contains(contentStr, expectedService) {
			t.Errorf("Expected service %s not found in output", expectedService)
		}
	}
}

// TestExportTargetsForDDoS tests the DDoS targets export functionality
func TestExportTargetsForDDoS(t *testing.T) {
	// Create test results with HTTP services
	results := &ScanResult{
		Timestamp: time.Now(),
		Hosts: []HostResult{
			{
				Target: "example.com",
				Status: HostUp,
				Ports: []PortResult{
					{
						Port:     80,
						Protocol: "TCP",
						State:    PortOpen,
						Service: ServiceInfo{
							Name: "http",
						},
					},
					{
						Port:     443,
						Protocol: "TCP",
						State:    PortOpen,
						Service: ServiceInfo{
							Name: "https",
						},
					},
					{
						Port:     22,
						Protocol: "TCP",
						State:    PortOpen,
						Service: ServiceInfo{
							Name: "ssh",
						},
					},
				},
			},
		},
	}

	// Create temporary output file
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "ddos-targets.txt")

	// Test export
	resultManager := NewResultManager()
	err := resultManager.ExportTargetsForDDoS(results, outputPath)
	if err != nil {
		t.Fatalf("Failed to export DDoS targets: %v", err)
	}

	// Read and verify output
	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output file: %v", err)
	}

	contentStr := string(content)

	// Should contain cURL commands for HTTP services
	expectedCommands := []string{
		"curl -X GET http://example.com",
		"curl -X GET https://example.com",
	}

	for _, expectedCmd := range expectedCommands {
		if !strings.Contains(contentStr, expectedCmd) {
			t.Errorf("Expected cURL command %s not found in output", expectedCmd)
		}
	}

	// Should not contain SSH service
	if strings.Contains(contentStr, "ssh") {
		t.Error("SSH service should not be included in DDoS targets export")
	}
}

// TestExportWithNoServices tests export functions with no suitable services
func TestExportWithNoServices(t *testing.T) {
	// Create test results with no web or auth services
	results := &ScanResult{
		Timestamp: time.Now(),
		Hosts: []HostResult{
			{
				Target: "192.168.1.1",
				Status: HostUp,
				Ports: []PortResult{
					{
						Port:     1234,
						Protocol: "TCP",
						State:    PortOpen,
						Service: ServiceInfo{
							Name: "unknown",
						},
					},
				},
			},
		},
	}

	tempDir := t.TempDir()
	resultManager := NewResultManager()

	// Test web services export - should fail
	outputPath := filepath.Join(tempDir, "web-services.txt")
	err := resultManager.ExportWebServicesForScanning(results, outputPath)
	if err == nil {
		t.Error("Expected error when exporting with no web services")
	}

	// Test auth services export - should fail
	outputPath = filepath.Join(tempDir, "auth-services.txt")
	err = resultManager.ExportTargetsForBruteForce(results, outputPath)
	if err == nil {
		t.Error("Expected error when exporting with no authentication services")
	}

	// Test DDoS targets export - should fail
	outputPath = filepath.Join(tempDir, "ddos-targets.txt")
	err = resultManager.ExportTargetsForDDoS(results, outputPath)
	if err == nil {
		t.Error("Expected error when exporting with no DDoS targets")
	}
}

// **Feature: network-mapper, Property 19: Integration Compatibility**
// **Validates: Requirements 9.2, 9.3**
// Property: For any discovered web service, export options should be provided for integration with other Letgo modules
func TestProperty19_IntegrationCompatibility(t *testing.T) {
	// Property-based test with 100 iterations as specified in design

	for i := range 100 {
		t.Run(fmt.Sprintf("iteration_%d", i), func(t *testing.T) {
			// Generate random scan results with various service types
			results := generateRandomScanResultWithServices()

			resultManager := NewResultManager()
			tempDir := t.TempDir()

			// Test web services export compatibility (Requirement 9.3)
			webServices := extractWebServicesFromResults(results)
			if len(webServices) > 0 {
				webOutputPath := filepath.Join(tempDir, "web-services.txt")
				err := resultManager.ExportWebServicesForScanning(results, webOutputPath)
				if err != nil {
					t.Errorf("Failed to export web services for scanning: %v", err)
					return
				}

				// Verify the exported file exists and contains valid URLs
				content, err := os.ReadFile(webOutputPath)
				if err != nil {
					t.Errorf("Failed to read exported web services file: %v", err)
					return
				}

				contentStr := string(content)
				for _, service := range webServices {
					if !strings.Contains(contentStr, service) {
						t.Errorf("Expected web service %s not found in exported file", service)
					}
				}
			}

			// Test authentication services export compatibility (Requirement 9.2)
			authServices := extractAuthServicesFromResults(results)
			if len(authServices) > 0 {
				authOutputPath := filepath.Join(tempDir, "auth-services.txt")
				err := resultManager.ExportTargetsForBruteForce(results, authOutputPath)
				if err != nil {
					t.Errorf("Failed to export authentication services for brute force: %v", err)
					return
				}

				// Verify the exported file exists and contains service information
				content, err := os.ReadFile(authOutputPath)
				if err != nil {
					t.Errorf("Failed to read exported auth services file: %v", err)
					return
				}

				contentStr := string(content)
				for _, service := range authServices {
					expectedLine := fmt.Sprintf("%s:%d|%s|%s|", service.Host, service.Port, service.Service, service.Protocol)
					if !strings.Contains(contentStr, expectedLine) {
						t.Errorf("Expected auth service %s not found in exported file", expectedLine)
					}
				}
			}

			// Test DDoS targets export compatibility (Requirement 9.2)
			ddosTargets := extractDDoSTargetsFromResults(results)
			if len(ddosTargets) > 0 {
				ddosOutputPath := filepath.Join(tempDir, "ddos-targets.txt")
				err := resultManager.ExportTargetsForDDoS(results, ddosOutputPath)
				if err != nil {
					t.Errorf("Failed to export DDoS targets: %v", err)
					return
				}

				// Verify the exported file exists and contains cURL commands
				content, err := os.ReadFile(ddosOutputPath)
				if err != nil {
					t.Errorf("Failed to read exported DDoS targets file: %v", err)
					return
				}

				contentStr := string(content)
				for _, target := range ddosTargets {
					expectedCmd := fmt.Sprintf("curl -X GET %s", target.URL)
					if !strings.Contains(contentStr, expectedCmd) {
						t.Errorf("Expected DDoS target %s not found in exported file", expectedCmd)
					}
				}
			}
		})
	}
}

// Helper functions for property testing

// generateRandomScanResultWithServices creates random scan results with various service types
func generateRandomScanResultWithServices() *ScanResult {
	rand.Seed(time.Now().UnixNano())

	// Generate 1-5 hosts
	numHosts := rand.Intn(5) + 1
	hosts := make([]HostResult, numHosts)

	// Common service ports and names
	webPorts := []int{80, 443, 8080, 8443, 3000, 8000}
	authPorts := []int{21, 22, 23, 25, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306, 1433, 1521}
	serviceNames := map[int]string{
		21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 80: "http", 110: "pop3",
		143: "imap", 443: "https", 993: "imaps", 995: "pop3s", 3389: "rdp",
		5432: "postgresql", 3306: "mysql", 1433: "mssql", 1521: "oracle",
		8080: "http-proxy", 8443: "https-alt", 3000: "http", 8000: "http-alt",
	}

	for i := range hosts {
		// Generate random IP address
		ip := fmt.Sprintf("192.168.%d.%d", rand.Intn(256), rand.Intn(256))

		// Generate 1-10 ports per host
		numPorts := rand.Intn(10) + 1
		ports := make([]PortResult, numPorts)

		for j := range ports {
			var port int
			var serviceName string

			// 70% chance of using a known service port
			if rand.Float32() < 0.7 {
				if rand.Float32() < 0.5 {
					// Web service
					port = webPorts[rand.Intn(len(webPorts))]
				} else {
					// Auth service
					port = authPorts[rand.Intn(len(authPorts))]
				}
				serviceName = serviceNames[port]
			} else {
				// Random port
				port = rand.Intn(65535) + 1
				serviceName = "unknown"
			}

			// Generate service info
			service := ServiceInfo{
				Name:       serviceName,
				Version:    fmt.Sprintf("%d.%d.%d", rand.Intn(10), rand.Intn(10), rand.Intn(10)),
				Product:    fmt.Sprintf("Product-%d", rand.Intn(100)),
				Confidence: rand.Float64() * 100,
				Banner:     fmt.Sprintf("Banner for %s on port %d", serviceName, port),
			}

			ports[j] = PortResult{
				Port:         port,
				Protocol:     "TCP",
				State:        PortOpen,
				Service:      service,
				Banner:       service.Banner,
				ResponseTime: time.Duration(rand.Intn(1000)) * time.Millisecond,
			}
		}

		hosts[i] = HostResult{
			Target:       ip,
			Status:       HostUp,
			Ports:        ports,
			ResponseTime: time.Duration(rand.Intn(100)) * time.Millisecond,
		}
	}

	return &ScanResult{
		Timestamp: time.Now(),
		Hosts:     hosts,
		Statistics: ScanStatistics{
			HostsScanned: numHosts,
			HostsTotal:   numHosts,
		},
	}
}

// extractWebServicesFromResults extracts web services from scan results (helper for testing)
func extractWebServicesFromResults(results *ScanResult) []string {
	var webServices []string
	webPorts := map[int]bool{80: true, 443: true, 8080: true, 8443: true, 8000: true, 8888: true, 3000: true, 5000: true}

	for _, host := range results.Hosts {
		if host.Status != HostUp {
			continue
		}

		for _, port := range host.Ports {
			if port.State != PortOpen {
				continue
			}

			// Check if it's a web service
			isWebService := webPorts[port.Port] ||
				strings.Contains(strings.ToLower(port.Service.Name), "http") ||
				strings.Contains(strings.ToLower(port.Service.Name), "web")

			if isWebService {
				scheme := "http"
				if port.Port == 443 || port.Port == 8443 || strings.Contains(strings.ToLower(port.Service.Name), "https") {
					scheme = "https"
				}

				url := fmt.Sprintf("%s://%s", scheme, host.Target)
				if (scheme == "http" && port.Port != 80) || (scheme == "https" && port.Port != 443) {
					url = fmt.Sprintf("%s://%s:%d", scheme, host.Target, port.Port)
				}

				webServices = append(webServices, url)
			}
		}
	}

	return webServices
}

// extractAuthServicesFromResults extracts authentication services from scan results (helper for testing)
func extractAuthServicesFromResults(results *ScanResult) []AuthService {
	var authServices []AuthService
	authPorts := map[int]string{
		21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 80: "http", 110: "pop3",
		143: "imap", 443: "https", 993: "imaps", 995: "pop3s", 3389: "rdp",
		5432: "postgresql", 3306: "mysql", 1433: "mssql", 1521: "oracle",
	}

	for _, host := range results.Hosts {
		if host.Status != HostUp {
			continue
		}

		for _, port := range host.Ports {
			if port.State != PortOpen {
				continue
			}

			// Check if it's an authentication service
			if serviceName, isAuthService := authPorts[port.Port]; isAuthService {
				service := AuthService{
					Host:        host.Target,
					Port:        port.Port,
					Service:     serviceName,
					Protocol:    port.Protocol,
					Banner:      port.Banner,
					ServiceInfo: port.Service,
				}
				authServices = append(authServices, service)
			}
		}
	}

	return authServices
}

// extractDDoSTargetsFromResults extracts DDoS targets from scan results (helper for testing)
func extractDDoSTargetsFromResults(results *ScanResult) []DDoSTarget {
	var ddosTargets []DDoSTarget

	for _, host := range results.Hosts {
		if host.Status != HostUp {
			continue
		}

		for _, port := range host.Ports {
			if port.State != PortOpen {
				continue
			}

			// Only include HTTP/HTTPS services
			isHTTPService := port.Port == 80 || port.Port == 443 || port.Port == 8080 || port.Port == 8443 ||
				strings.Contains(strings.ToLower(port.Service.Name), "http")

			if isHTTPService {
				scheme := "http"
				if port.Port == 443 || port.Port == 8443 || strings.Contains(strings.ToLower(port.Service.Name), "https") {
					scheme = "https"
				}

				url := fmt.Sprintf("%s://%s", scheme, host.Target)
				if (scheme == "http" && port.Port != 80) || (scheme == "https" && port.Port != 443) {
					url = fmt.Sprintf("%s://%s:%d", scheme, host.Target, port.Port)
				}

				target := DDoSTarget{
					URL:         url,
					Host:        host.Target,
					Port:        port.Port,
					Scheme:      scheme,
					ServiceInfo: port.Service,
				}
				ddosTargets = append(ddosTargets, target)
			}
		}
	}

	return ddosTargets
}
