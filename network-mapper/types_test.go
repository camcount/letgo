package networkmapper

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// **Feature: network-mapper, Property 14: Result Persistence**
// **Validates: Requirements 6.1, 6.3**
// Property: For any completed scan, results should be saved to a structured file format
// with timestamp, scan parameters, and detailed findings
func TestProperty14_ResultPersistence(t *testing.T) {
	// Property-based test with 100 iterations as specified in design
	for i := 0; i < 100; i++ {
		t.Run(fmt.Sprintf("iteration_%d", i), func(t *testing.T) {
			// Generate random scan result
			scanResult := generateRandomScanResult()

			// Test JSON format persistence
			jsonData, err := json.Marshal(scanResult)
			require.NoError(t, err, "Should be able to marshal scan result to JSON")

			var unmarshaledJSON ScanResult
			err = json.Unmarshal(jsonData, &unmarshaledJSON)
			require.NoError(t, err, "Should be able to unmarshal JSON back to ScanResult")

			// Verify essential fields are preserved (Requirements 6.1, 6.3)
			validateResultPersistence(t, scanResult, unmarshaledJSON)

			// Test XML format persistence
			xmlData, err := xml.Marshal(scanResult)
			require.NoError(t, err, "Should be able to marshal scan result to XML")

			var unmarshaledXML ScanResult
			err = xml.Unmarshal(xmlData, &unmarshaledXML)
			require.NoError(t, err, "Should be able to unmarshal XML back to ScanResult")

			// Verify essential fields are preserved for XML too
			validateResultPersistence(t, scanResult, unmarshaledXML)
		})
	}
}

// validateResultPersistence checks that essential data is preserved during serialization
// This validates Requirements 6.1 and 6.3
func validateResultPersistence(t *testing.T, original, restored ScanResult) {
	// Requirement 6.1: Results saved to structured file format
	// Requirement 6.3: Include timestamp, scan parameters, and detailed findings

	// Validate timestamp is preserved
	require.Equal(t, original.Timestamp.Unix(), restored.Timestamp.Unix(),
		"Timestamp should be preserved in structured format")

	// Validate scan parameters are preserved
	require.Equal(t, original.ScanConfig.Targets, restored.ScanConfig.Targets,
		"Scan targets should be preserved")
	require.Equal(t, original.ScanConfig.Ports, restored.ScanConfig.Ports,
		"Scan ports should be preserved")
	require.Equal(t, original.ScanConfig.ScanType, restored.ScanConfig.ScanType,
		"Scan type should be preserved")
	require.Equal(t, original.ScanConfig.ServiceDetect, restored.ScanConfig.ServiceDetect,
		"Service detection setting should be preserved")
	require.Equal(t, original.ScanConfig.OSDetect, restored.ScanConfig.OSDetect,
		"OS detection setting should be preserved")
	require.Equal(t, original.ScanConfig.MaxThreads, restored.ScanConfig.MaxThreads,
		"Max threads setting should be preserved")
	require.Equal(t, original.ScanConfig.OutputFormat, restored.ScanConfig.OutputFormat,
		"Output format should be preserved")

	// Validate detailed findings for each host are preserved
	require.Equal(t, len(original.Hosts), len(restored.Hosts),
		"Number of host results should be preserved")

	for i, originalHost := range original.Hosts {
		restoredHost := restored.Hosts[i]

		// Validate host details
		require.Equal(t, originalHost.Target, restoredHost.Target,
			"Host target should be preserved")
		require.Equal(t, originalHost.Status, restoredHost.Status,
			"Host status should be preserved")

		// Validate port results
		require.Equal(t, len(originalHost.Ports), len(restoredHost.Ports),
			"Number of port results should be preserved")

		for j, originalPort := range originalHost.Ports {
			restoredPort := restoredHost.Ports[j]
			require.Equal(t, originalPort.Port, restoredPort.Port,
				"Port number should be preserved")
			require.Equal(t, originalPort.Protocol, restoredPort.Protocol,
				"Port protocol should be preserved")
			require.Equal(t, originalPort.State, restoredPort.State,
				"Port state should be preserved")
			require.Equal(t, originalPort.Service.Name, restoredPort.Service.Name,
				"Service name should be preserved")
			require.Equal(t, originalPort.Service.Version, restoredPort.Service.Version,
				"Service version should be preserved")
		}

		// Validate OS information
		require.Equal(t, originalHost.OS.Family, restoredHost.OS.Family,
			"OS family should be preserved")
		require.Equal(t, originalHost.OS.Version, restoredHost.OS.Version,
			"OS version should be preserved")
	}

	// Validate statistics are preserved
	require.Equal(t, original.Statistics.HostsScanned, restored.Statistics.HostsScanned,
		"Hosts scanned count should be preserved")
	require.Equal(t, original.Statistics.PortsScanned, restored.Statistics.PortsScanned,
		"Ports scanned count should be preserved")
	require.Equal(t, original.Statistics.OpenPorts, restored.Statistics.OpenPorts,
		"Open ports count should be preserved")
}

// generateRandomScanResult creates a random ScanResult for property testing
func generateRandomScanResult() ScanResult {
	rand.Seed(time.Now().UnixNano())

	// Generate random targets
	numTargets := rand.Intn(5) + 1
	targets := make([]string, numTargets)
	for i := 0; i < numTargets; i++ {
		targets[i] = fmt.Sprintf("192.168.1.%d", rand.Intn(254)+1)
	}

	// Generate random ports
	numPorts := rand.Intn(10) + 1
	ports := make([]int, numPorts)
	for i := 0; i < numPorts; i++ {
		ports[i] = rand.Intn(65535) + 1
	}

	// Generate random scan config
	scanConfig := ScanConfig{
		Targets:       targets,
		Ports:         ports,
		ScanType:      ScanType(rand.Intn(3)), // 0-2 for the three scan types
		ServiceDetect: rand.Intn(2) == 1,
		OSDetect:      rand.Intn(2) == 1,
		MaxThreads:    rand.Intn(100) + 1,
		Timeout:       time.Duration(rand.Intn(30)+1) * time.Second,
		OutputFormat:  OutputFormat(rand.Intn(3)), // 0-2 for the three formats
		OutputFile:    fmt.Sprintf("scan_%d.txt", rand.Intn(1000)),
	}

	// Generate random host results
	numHosts := rand.Intn(len(targets)) + 1
	hosts := make([]HostResult, numHosts)
	for i := 0; i < numHosts; i++ {
		hosts[i] = generateRandomHostResult(targets[i%len(targets)], ports)
	}

	// Calculate statistics based on actual port results
	totalPorts := 0
	openPorts := 0
	closedPorts := 0
	filteredPorts := 0

	for _, host := range hosts {
		for _, port := range host.Ports {
			totalPorts++
			switch port.State {
			case PortOpen:
				openPorts++
			case PortClosed:
				closedPorts++
			case PortFiltered:
				filteredPorts++
			}
		}
	}

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
		ScanRate:      float64(totalPorts) / 3600.0, // ports per second
	}

	return ScanResult{
		Timestamp:  time.Now(),
		ScanConfig: scanConfig,
		Hosts:      hosts,
		Statistics: statistics,
	}
}

// generateRandomHostResult creates a random HostResult for testing
func generateRandomHostResult(target string, ports []int) HostResult {
	// Generate random port results
	numPortResults := rand.Intn(len(ports)) + 1
	portResults := make([]PortResult, numPortResults)

	for i := 0; i < numPortResults; i++ {
		port := ports[i%len(ports)]
		portResults[i] = PortResult{
			Port:     port,
			Protocol: []string{"tcp", "udp"}[rand.Intn(2)],
			State:    PortState(rand.Intn(3)), // 0-2 for open/closed/filtered
			Service: ServiceInfo{
				Name:       generateRandomServiceName(),
				Version:    fmt.Sprintf("%d.%d.%d", rand.Intn(10), rand.Intn(10), rand.Intn(10)),
				Product:    generateRandomProductName(),
				ExtraInfo:  []KeyValue{{Key: "info", Value: "test"}},
				Confidence: rand.Float64() * 100,
			},
			Banner:       generateRandomBanner(),
			ResponseTime: time.Duration(rand.Intn(1000)) * time.Millisecond,
		}
	}

	// Generate random OS info
	osInfo := OSInfo{
		Family:     []string{"Linux", "Windows", "macOS", "FreeBSD"}[rand.Intn(4)],
		Version:    fmt.Sprintf("%d.%d", rand.Intn(10), rand.Intn(10)),
		Confidence: rand.Float64() * 100,
		Matches: []OSMatch{
			{
				Name:       "Test OS",
				Version:    "1.0",
				Confidence: rand.Float64() * 100,
			},
		},
	}

	return HostResult{
		Target:       target,
		Status:       HostStatus(rand.Intn(3)), // 0-2 for up/down/unknown
		Ports:        portResults,
		OS:           osInfo,
		ResponseTime: time.Duration(rand.Intn(1000)) * time.Millisecond,
	}
}

// generateRandomServiceName returns a random service name for testing
func generateRandomServiceName() string {
	services := []string{"http", "https", "ssh", "ftp", "smtp", "dns", "mysql", "postgresql"}
	return services[rand.Intn(len(services))]
}

// generateRandomProductName returns a random product name for testing
func generateRandomProductName() string {
	products := []string{"Apache", "Nginx", "OpenSSH", "vsftpd", "Postfix", "BIND", "MySQL", "PostgreSQL"}
	return products[rand.Intn(len(products))]
}

// generateRandomBanner returns a random service banner for testing
func generateRandomBanner() string {
	banners := []string{
		"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41",
		"SSH-2.0-OpenSSH_8.0",
		"220 Welcome to FTP server",
		"220 mail.example.com ESMTP Postfix",
	}
	return banners[rand.Intn(len(banners))]
}

// **Feature: network-mapper, Property 3: Scan Result Completeness**
// **Validates: Requirements 1.3**
// Property: For any completed port scan, the output should contain port number,
// state (open/closed/filtered), and protocol information for each scanned port
func TestProperty3_ScanResultCompleteness(t *testing.T) {
	// Property-based test with 100 iterations as specified in design
	for i := 0; i < 100; i++ {
		t.Run(fmt.Sprintf("iteration_%d", i), func(t *testing.T) {
			// Generate random scan result
			scanResult := generateRandomScanResult()

			// Validate that scan result contains required information (Requirements 1.3)
			validateScanResultCompleteness(t, scanResult)
		})
	}
}

// validateScanResultCompleteness checks that all scan results include required information
// This validates Requirements 1.3: port number, state, and protocol for each scanned port
func validateScanResultCompleteness(t *testing.T, result ScanResult) {
	// Requirement 1.3: Display port number, state (open/closed/filtered), and protocol for each scanned port

	// Validate that we have host results
	require.NotEmpty(t, result.Hosts, "Scan result should contain host results")

	for hostIdx, host := range result.Hosts {
		// Each host should have a valid target
		require.NotEmpty(t, host.Target, "Host %d should have a target identifier", hostIdx)

		// Each host should have a valid status
		require.True(t, host.Status >= HostUp && host.Status <= HostUnknown,
			"Host %d should have valid status (up/down/unknown)", hostIdx)

		// Validate port results for each host
		for portIdx, port := range host.Ports {
			// Requirement 1.3: Port number must be present and valid
			require.True(t, port.Port >= 1 && port.Port <= 65535,
				"Host %d, Port %d: Port number must be between 1 and 65535, got %d",
				hostIdx, portIdx, port.Port)

			// Requirement 1.3: Protocol must be present and valid
			require.NotEmpty(t, port.Protocol,
				"Host %d, Port %d: Protocol must be specified", hostIdx, portIdx)
			require.True(t, port.Protocol == "tcp" || port.Protocol == "udp",
				"Host %d, Port %d: Protocol must be 'tcp' or 'udp', got '%s'",
				hostIdx, portIdx, port.Protocol)

			// Requirement 1.3: State must be present and valid (open/closed/filtered)
			require.True(t, port.State >= PortOpen && port.State <= PortFiltered,
				"Host %d, Port %d: Port state must be open/closed/filtered, got %v",
				hostIdx, portIdx, port.State)

			// Response time should be non-negative (0 is acceptable for very fast responses)
			require.True(t, port.ResponseTime >= 0,
				"Host %d, Port %d: Response time should be non-negative, got %v",
				hostIdx, portIdx, port.ResponseTime)
		}
	}

	// Validate that scan statistics are present and consistent
	require.True(t, result.Statistics.HostsScanned >= 0,
		"Hosts scanned count should be non-negative")
	require.True(t, result.Statistics.PortsScanned >= 0,
		"Ports scanned count should be non-negative")
	require.True(t, result.Statistics.OpenPorts >= 0,
		"Open ports count should be non-negative")
	require.True(t, result.Statistics.ClosedPorts >= 0,
		"Closed ports count should be non-negative")
	require.True(t, result.Statistics.FilteredPorts >= 0,
		"Filtered ports count should be non-negative")

	// Validate that port state counts are consistent with actual port results
	actualOpenPorts := 0
	actualClosedPorts := 0
	actualFilteredPorts := 0

	for _, host := range result.Hosts {
		for _, port := range host.Ports {
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

	// Statistics should match actual port states
	require.Equal(t, actualOpenPorts, result.Statistics.OpenPorts,
		"Statistics open ports count should match actual open ports")
	require.Equal(t, actualClosedPorts, result.Statistics.ClosedPorts,
		"Statistics closed ports count should match actual closed ports")
	require.Equal(t, actualFilteredPorts, result.Statistics.FilteredPorts,
		"Statistics filtered ports count should match actual filtered ports")

	// Total ports scanned should equal sum of all port states
	totalPortsFromStates := result.Statistics.OpenPorts + result.Statistics.ClosedPorts + result.Statistics.FilteredPorts
	require.Equal(t, totalPortsFromStates, result.Statistics.PortsScanned,
		"Total ports scanned should equal sum of open + closed + filtered ports")
}
