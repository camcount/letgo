package networkmapper

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// **Feature: network-mapper, Property 15: Export Format Support**
// **Validates: Requirements 6.2**
// Property: For any result export operation, the system should support JSON, XML, and plain text output formats
func TestProperty15_ExportFormatSupport(t *testing.T) {
	rm := NewResultManager()

	// Property-based test with 100 iterations as specified in design
	for i := range 100 {
		t.Run(fmt.Sprintf("iteration_%d", i), func(t *testing.T) {
			// Generate random scan result
			scanResult := generateRandomScanResult()

			// Test JSON format support (Requirement 6.2)
			jsonData, err := rm.ExportResults(&scanResult, OutputFormatJSON)
			require.NoError(t, err, "Should support JSON export format")
			require.NotEmpty(t, jsonData, "JSON export should produce non-empty data")

			// Verify JSON is valid by unmarshaling
			var jsonResult ScanResult
			err = json.Unmarshal(jsonData, &jsonResult)
			require.NoError(t, err, "Exported JSON should be valid and parseable")

			// Test XML format support (Requirement 6.2)
			xmlData, err := rm.ExportResults(&scanResult, OutputFormatXML)
			require.NoError(t, err, "Should support XML export format")
			require.NotEmpty(t, xmlData, "XML export should produce non-empty data")

			// Verify XML is valid by unmarshaling
			var xmlResult ScanResult
			err = xml.Unmarshal(xmlData, &xmlResult)
			require.NoError(t, err, "Exported XML should be valid and parseable")

			// Test plain text format support (Requirement 6.2)
			textData, err := rm.ExportResults(&scanResult, OutputFormatText)
			require.NoError(t, err, "Should support plain text export format")
			require.NotEmpty(t, textData, "Text export should produce non-empty data")

			// Verify text format contains expected sections
			textStr := string(textData)
			require.Contains(t, textStr, "Network Scan Results", "Text format should contain header")
			require.Contains(t, textStr, "Scan Statistics", "Text format should contain statistics section")
			require.Contains(t, textStr, "Host Results", "Text format should contain host results section")

			// Verify all formats contain essential scan information
			validateExportedData(t, scanResult, jsonResult, "JSON")
			validateExportedData(t, scanResult, xmlResult, "XML")
			validateTextFormat(t, scanResult, textStr)
		})
	}
}

// **Feature: network-mapper, Property 16: Result Organization**
// **Validates: Requirements 6.4**
// Property: For any exported results, data should be organized by host with nested port and service information
func TestProperty16_ResultOrganization(t *testing.T) {
	rm := NewResultManager()

	// Property-based test with 100 iterations as specified in design
	for i := range 100 {
		t.Run(fmt.Sprintf("iteration_%d", i), func(t *testing.T) {
			// Generate random scan result with multiple hosts and ports
			scanResult := generateRandomScanResultWithMultipleHosts()

			// Test JSON organization (Requirement 6.4)
			jsonData, err := rm.ExportResults(scanResult, OutputFormatJSON)
			require.NoError(t, err, "Should export JSON successfully")

			var jsonResult ScanResult
			err = json.Unmarshal(jsonData, &jsonResult)
			require.NoError(t, err, "Should parse exported JSON")

			validateResultOrganization(t, jsonResult, "JSON")

			// Test XML organization (Requirement 6.4)
			xmlData, err := rm.ExportResults(scanResult, OutputFormatXML)
			require.NoError(t, err, "Should export XML successfully")

			var xmlResult ScanResult
			err = xml.Unmarshal(xmlData, &xmlResult)
			require.NoError(t, err, "Should parse exported XML")

			validateResultOrganization(t, xmlResult, "XML")

			// Test text format organization (Requirement 6.4)
			textData, err := rm.ExportResults(scanResult, OutputFormatText)
			require.NoError(t, err, "Should export text successfully")

			validateTextOrganization(t, *scanResult, string(textData))
		})
	}
}

// validateExportedData verifies that exported data preserves essential information
func validateExportedData(t *testing.T, original, exported ScanResult, format string) {
	require.Equal(t, original.Timestamp.Unix(), exported.Timestamp.Unix(),
		"%s format should preserve timestamp", format)
	require.Equal(t, len(original.Hosts), len(exported.Hosts),
		"%s format should preserve number of hosts", format)
	require.Equal(t, original.ScanConfig.Targets, exported.ScanConfig.Targets,
		"%s format should preserve scan targets", format)
	require.Equal(t, original.Statistics.OpenPorts, exported.Statistics.OpenPorts,
		"%s format should preserve statistics", format)
}

// validateTextFormat verifies that text format contains expected information
func validateTextFormat(t *testing.T, original ScanResult, textOutput string) {
	// Should contain scan configuration information
	require.Contains(t, textOutput, original.ScanConfig.ScanType.String(),
		"Text format should contain scan type")

	// Should contain each target host
	for _, target := range original.ScanConfig.Targets {
		require.Contains(t, textOutput, target,
			"Text format should contain target %s", target)
	}

	// Should contain statistics
	require.Contains(t, textOutput, fmt.Sprintf("Open Ports: %d", original.Statistics.OpenPorts),
		"Text format should contain open ports count")
	require.Contains(t, textOutput, fmt.Sprintf("Hosts Scanned: %d", original.Statistics.HostsScanned),
		"Text format should contain hosts scanned count")
}

// validateResultOrganization verifies that results are organized by host with nested data
func validateResultOrganization(t *testing.T, result ScanResult, format string) {
	// Requirement 6.4: Data organized by host with nested port and service information

	for _, host := range result.Hosts {
		// Each host should have a target identifier
		require.NotEmpty(t, host.Target, "%s format: Host should have target identifier", format)

		// Each host should have status information
		require.True(t, host.Status >= HostUp && host.Status <= HostUnknown,
			"%s format: Host should have valid status", format)

		// Port information should be nested under each host
		for _, port := range host.Ports {
			require.True(t, port.Port > 0 && port.Port <= 65535,
				"%s format: Port should have valid port number", format)
			require.NotEmpty(t, port.Protocol,
				"%s format: Port should have protocol information", format)
			require.True(t, port.State >= PortOpen && port.State <= PortFiltered,
				"%s format: Port should have valid state", format)

			// Service information should be nested under each port
			if port.Service.Name != "" {
				require.NotEmpty(t, port.Service.Name,
					"%s format: Service should have name if detected", format)
				require.True(t, port.Service.Confidence >= 0 && port.Service.Confidence <= 100,
					"%s format: Service confidence should be valid percentage", format)
			}
		}

		// OS information should be nested under each host
		if host.OS.Family != "" {
			require.NotEmpty(t, host.OS.Family,
				"%s format: OS should have family if detected", format)
			require.True(t, host.OS.Confidence >= 0 && host.OS.Confidence <= 100,
				"%s format: OS confidence should be valid percentage", format)
		}
	}
}

// validateTextOrganization verifies that text format organizes data by host
func validateTextOrganization(t *testing.T, original ScanResult, textOutput string) {
	// Requirement 6.4: Text format should organize data by host with nested information

	for _, host := range original.Hosts {
		// Find the host section in text output
		hostSection := fmt.Sprintf("Host: %s", host.Target)
		require.Contains(t, textOutput, hostSection,
			"Text format should contain host section for %s", host.Target)

		// Find the position of this host section
		hostIndex := strings.Index(textOutput, hostSection)
		require.True(t, hostIndex >= 0, "Should find host section")

		// Check that port information appears after host information
		for _, port := range host.Ports {
			portInfo := fmt.Sprintf("%d/%s", port.Port, port.Protocol)
			portIndex := strings.Index(textOutput[hostIndex:], portInfo)
			require.True(t, portIndex >= 0,
				"Port %s should appear in host %s section", portInfo, host.Target)

			// If service is detected, it should appear near the port
			if port.Service.Name != "" {
				serviceIndex := strings.Index(textOutput[hostIndex:], port.Service.Name)
				require.True(t, serviceIndex >= 0,
					"Service %s should appear in host %s section", port.Service.Name, host.Target)
			}
		}

		// Check that OS information appears in host section if available
		if host.OS.Family != "" {
			osInfo := fmt.Sprintf("OS: %s", host.OS.Family)
			osIndex := strings.Index(textOutput[hostIndex:], osInfo)
			require.True(t, osIndex >= 0,
				"OS info should appear in host %s section", host.Target)
		}
	}
}

// generateRandomScanResultWithMultipleHosts creates a scan result with multiple hosts for organization testing
func generateRandomScanResultWithMultipleHosts() *ScanResult {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	// Generate multiple targets (at least 2)
	numTargets := r.Intn(4) + 2 // 2-5 targets
	targets := make([]string, numTargets)
	for i := range numTargets {
		targets[i] = fmt.Sprintf("192.168.1.%d", r.Intn(254)+1)
	}

	// Generate multiple ports (at least 3)
	numPorts := r.Intn(8) + 3 // 3-10 ports
	ports := make([]int, numPorts)
	for i := range numPorts {
		ports[i] = r.Intn(65535) + 1
	}

	// Generate scan config
	scanConfig := ScanConfig{
		Targets:       targets,
		Ports:         ports,
		ScanType:      ScanType(r.Intn(3)),
		ServiceDetect: true, // Enable service detection for testing
		OSDetect:      true, // Enable OS detection for testing
		MaxThreads:    r.Intn(100) + 1,
		Timeout:       time.Duration(r.Intn(30)+1) * time.Second,
		OutputFormat:  OutputFormat(r.Intn(3)),
		OutputFile:    fmt.Sprintf("scan_%d.txt", r.Intn(1000)),
	}

	// Generate host results for each target
	hosts := make([]HostResult, len(targets))
	for i, target := range targets {
		hosts[i] = generateRandomHostResultWithServices(target, ports, r)
	}

	// Generate statistics
	totalPorts := len(hosts) * len(ports)
	openPorts := r.Intn(totalPorts)
	closedPorts := r.Intn(totalPorts - openPorts)
	filteredPorts := totalPorts - openPorts - closedPorts

	statistics := ScanStatistics{
		HostsScanned:  len(hosts),
		HostsTotal:    len(targets),
		PortsScanned:  totalPorts,
		PortsTotal:    totalPorts,
		OpenPorts:     openPorts,
		ClosedPorts:   closedPorts,
		FilteredPorts: filteredPorts,
		StartTime:     time.Now().Add(-time.Hour),
		EndTime:       time.Now(),
		ElapsedTime:   time.Hour,
		ScanRate:      float64(totalPorts) / 3600.0,
	}

	return &ScanResult{
		Timestamp:  time.Now(),
		ScanConfig: scanConfig,
		Hosts:      hosts,
		Statistics: statistics,
	}
}

// generateRandomHostResultWithServices creates a host result with detailed service information
func generateRandomHostResultWithServices(target string, ports []int, r *rand.Rand) HostResult {
	// Generate port results with services
	numPortResults := r.Intn(len(ports)) + 1
	portResults := make([]PortResult, numPortResults)

	services := []string{"http", "https", "ssh", "ftp", "smtp", "dns", "mysql", "postgresql", "redis", "mongodb"}
	products := []string{"Apache", "Nginx", "OpenSSH", "vsftpd", "Postfix", "BIND", "MySQL", "PostgreSQL", "Redis", "MongoDB"}
	banners := []string{
		"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41",
		"SSH-2.0-OpenSSH_8.0",
		"220 Welcome to FTP server",
		"220 mail.example.com ESMTP Postfix",
		"BIND 9.16.1",
	}

	for i := range numPortResults {
		port := ports[i%len(ports)]
		serviceIdx := r.Intn(len(services))

		portResults[i] = PortResult{
			Port:     port,
			Protocol: []string{"tcp", "udp"}[r.Intn(2)],
			State:    PortState(r.Intn(3)),
			Service: ServiceInfo{
				Name:       services[serviceIdx],
				Version:    fmt.Sprintf("%d.%d.%d", r.Intn(10), r.Intn(10), r.Intn(10)),
				Product:    products[serviceIdx%len(products)],
				ExtraInfo:  []KeyValue{{Key: "info", Value: "test data"}},
				Confidence: r.Float64() * 100,
				Banner:     banners[r.Intn(len(banners))],
			},
			Banner:       banners[r.Intn(len(banners))],
			ResponseTime: time.Duration(r.Intn(1000)) * time.Millisecond,
		}
	}

	// Generate OS info with multiple matches
	osMatches := []OSMatch{
		{
			Name:       "Linux Ubuntu 20.04",
			Version:    "20.04",
			Confidence: r.Float64() * 100,
		},
		{
			Name:       "Linux Debian 10",
			Version:    "10",
			Confidence: r.Float64() * 80,
		},
	}

	osInfo := OSInfo{
		Family:     []string{"Linux", "Windows", "macOS", "FreeBSD"}[r.Intn(4)],
		Version:    fmt.Sprintf("%d.%d", r.Intn(10), r.Intn(10)),
		Confidence: r.Float64() * 100,
		Matches:    osMatches,
	}

	return HostResult{
		Target:       target,
		Status:       HostStatus(r.Intn(3)),
		Ports:        portResults,
		OS:           osInfo,
		ResponseTime: time.Duration(r.Intn(1000)) * time.Millisecond,
	}
}

// Test file operations (save/load)
func TestResultManagerFileOperations(t *testing.T) {
	rm := NewResultManager()

	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Generate test data
	scanResult := generateRandomScanResult()

	// Test JSON save/load
	jsonFile := filepath.Join(tempDir, "test_results.json")
	err := rm.SaveResults(&scanResult, OutputFormatJSON, jsonFile)
	require.NoError(t, err, "Should save JSON results successfully")

	loadedJSON, err := rm.LoadResults(jsonFile)
	require.NoError(t, err, "Should load JSON results successfully")
	validateExportedData(t, scanResult, *loadedJSON, "JSON file")

	// Test XML save/load
	xmlFile := filepath.Join(tempDir, "test_results.xml")
	err = rm.SaveResults(&scanResult, OutputFormatXML, xmlFile)
	require.NoError(t, err, "Should save XML results successfully")

	loadedXML, err := rm.LoadResults(xmlFile)
	require.NoError(t, err, "Should load XML results successfully")
	validateExportedData(t, scanResult, *loadedXML, "XML file")

	// Test text save (load not supported for text format)
	textFile := filepath.Join(tempDir, "test_results.txt")
	err = rm.SaveResults(&scanResult, OutputFormatText, textFile)
	require.NoError(t, err, "Should save text results successfully")

	// Verify text file exists and has content
	textData, err := os.ReadFile(textFile)
	require.NoError(t, err, "Should read text file successfully")
	require.NotEmpty(t, textData, "Text file should have content")
	validateTextFormat(t, scanResult, string(textData))
}

// Test error conditions
func TestResultManagerErrorConditions(t *testing.T) {
	rm := NewResultManager()

	// Test nil results
	_, err := rm.ExportResults(nil, OutputFormatJSON)
	require.Error(t, err, "Should error on nil results")

	err = rm.SaveResults(nil, OutputFormatJSON, "test.json")
	require.Error(t, err, "Should error on nil results for save")

	// Test invalid format (this would require extending OutputFormat enum)
	// For now, test with valid formats

	// Test loading non-existent file
	_, err = rm.LoadResults("non_existent_file.json")
	require.Error(t, err, "Should error on non-existent file")

	// Test loading with empty filename
	_, err = rm.LoadResults("")
	require.Error(t, err, "Should error on empty filename")
}
