package networkmapper

import (
	"strings"
	"testing"
	"testing/quick"
	"time"
)

// **Feature: network-mapper, Property 33: Geolocation Information Inclusion**
// **Validates: Requirements 12.3**
// Property: For any IP address where geolocation data is available, country and region information should be included
func TestProperty_GeolocationInformationInclusion(t *testing.T) {
	config := &quick.Config{MaxCount: 100}

	property := func(hostname string, hasGeoData bool) bool {
		// Ensure we have a valid hostname
		if hostname == "" || len(hostname) > 50 || !isValidTestHostname(hostname) {
			hostname = "example.com"
		}

		// Create test infrastructure info with geolocation data
		var infraInfo InfrastructureInfo
		if hasGeoData {
			// Create mock geolocation data
			infraInfo = InfrastructureInfo{
				HostingProvider: "Test Provider",
				CloudPlatform:   "Test Cloud",
				DataCenter:      "Test Region, Test Country",
				NetworkInfo: NetworkInfo{
					ASN:          "AS12345",
					Organization: "Test Organization",
				},
			}
		}

		// Create resolved IP with geolocation context
		resolvedIPs := []ResolvedIP{
			{
				IP:         "192.168.1.1",
				Type:       "IPv4",
				Hostname:   hostname,
				ResolvedAt: time.Now(),
			},
		}

		hostResult := HostResult{
			Target:         hostname,
			ResolvedIPs:    resolvedIPs,
			Status:         HostUp,
			Ports:          []PortResult{},
			Infrastructure: infraInfo,
			ResponseTime:   100 * time.Millisecond,
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

		// If geolocation data is available, verify it's included in output
		if hasGeoData {
			// Check for infrastructure section
			if !strings.Contains(outputStr, "Infrastructure:") {
				return false
			}

			// Check for hosting provider information
			if infraInfo.HostingProvider != "" && !strings.Contains(outputStr, infraInfo.HostingProvider) {
				return false
			}

			// Check for cloud platform information
			if infraInfo.CloudPlatform != "" && !strings.Contains(outputStr, infraInfo.CloudPlatform) {
				return false
			}

			// Check for data center/region information
			if infraInfo.DataCenter != "" && !strings.Contains(outputStr, infraInfo.DataCenter) {
				return false
			}

			// Check for ASN information
			if infraInfo.NetworkInfo.ASN != "" && !strings.Contains(outputStr, infraInfo.NetworkInfo.ASN) {
				return false
			}

			// Check for organization information
			if infraInfo.NetworkInfo.Organization != "" && !strings.Contains(outputStr, infraInfo.NetworkInfo.Organization) {
				return false
			}
		}

		return true
	}

	if err := quick.Check(property, config); err != nil {
		t.Errorf("Property failed: %v", err)
	}
}

// TestProperty_GeolocationInformationInclusion_JSON tests the same property for JSON output
func TestProperty_GeolocationInformationInclusion_JSON(t *testing.T) {
	config := &quick.Config{MaxCount: 100}

	property := func(hostname string, hasGeoData bool) bool {
		// Ensure we have a valid hostname
		if hostname == "" || len(hostname) > 50 || !isValidTestHostname(hostname) {
			hostname = "example.com"
		}

		// Create test infrastructure info with geolocation data
		var infraInfo InfrastructureInfo
		if hasGeoData {
			// Create mock geolocation data
			infraInfo = InfrastructureInfo{
				HostingProvider: "Test Provider",
				CloudPlatform:   "Test Cloud",
				DataCenter:      "Test Region, Test Country",
				NetworkInfo: NetworkInfo{
					ASN:          "AS12345",
					Organization: "Test Organization",
				},
			}
		}

		// Create resolved IP with geolocation context
		resolvedIPs := []ResolvedIP{
			{
				IP:         "192.168.1.1",
				Type:       "IPv4",
				Hostname:   hostname,
				ResolvedAt: time.Now(),
			},
		}

		hostResult := HostResult{
			Target:         hostname,
			ResolvedIPs:    resolvedIPs,
			Status:         HostUp,
			Ports:          []PortResult{},
			Infrastructure: infraInfo,
			ResponseTime:   100 * time.Millisecond,
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

		// If geolocation data is available, verify it's included in JSON
		if hasGeoData {
			// Check for infrastructure field in JSON
			if !strings.Contains(outputStr, "infrastructure") {
				return false
			}

			// Check for hosting provider information
			if infraInfo.HostingProvider != "" && !strings.Contains(outputStr, infraInfo.HostingProvider) {
				return false
			}

			// Check for cloud platform information
			if infraInfo.CloudPlatform != "" && !strings.Contains(outputStr, infraInfo.CloudPlatform) {
				return false
			}

			// Check for data center/region information
			if infraInfo.DataCenter != "" && !strings.Contains(outputStr, infraInfo.DataCenter) {
				return false
			}

			// Check for network info
			if !strings.Contains(outputStr, "network_info") {
				return false
			}
		}

		return true
	}

	if err := quick.Check(property, config); err != nil {
		t.Errorf("Property failed: %v", err)
	}
}

// TestProperty_GeolocationInformationInclusion_XML tests the same property for XML output
func TestProperty_GeolocationInformationInclusion_XML(t *testing.T) {
	config := &quick.Config{MaxCount: 100}

	property := func(hostname string, hasGeoData bool) bool {
		// Ensure we have a valid hostname
		if hostname == "" || len(hostname) > 50 || !isValidTestHostname(hostname) {
			hostname = "example.com"
		}

		// Create test infrastructure info with geolocation data
		var infraInfo InfrastructureInfo
		if hasGeoData {
			// Create mock geolocation data
			infraInfo = InfrastructureInfo{
				HostingProvider: "Test Provider",
				CloudPlatform:   "Test Cloud",
				DataCenter:      "Test Region, Test Country",
				NetworkInfo: NetworkInfo{
					ASN:          "AS12345",
					Organization: "Test Organization",
				},
			}
		}

		// Create resolved IP with geolocation context
		resolvedIPs := []ResolvedIP{
			{
				IP:         "192.168.1.1",
				Type:       "IPv4",
				Hostname:   hostname,
				ResolvedAt: time.Now(),
			},
		}

		hostResult := HostResult{
			Target:         hostname,
			ResolvedIPs:    resolvedIPs,
			Status:         HostUp,
			Ports:          []PortResult{},
			Infrastructure: infraInfo,
			ResponseTime:   100 * time.Millisecond,
		}

		scanResult := &ScanResult{
			Timestamp: time.Time{},
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

		// If geolocation data is available, verify it's included in XML
		if hasGeoData {
			// Check for infrastructure element in XML
			if !strings.Contains(outputStr, "<Infrastructure>") && !strings.Contains(outputStr, "<infrastructure>") {
				return false
			}

			// Check for hosting provider information
			if infraInfo.HostingProvider != "" && !strings.Contains(outputStr, infraInfo.HostingProvider) {
				return false
			}

			// Check for cloud platform information
			if infraInfo.CloudPlatform != "" && !strings.Contains(outputStr, infraInfo.CloudPlatform) {
				return false
			}
		}

		return true
	}

	if err := quick.Check(property, config); err != nil {
		t.Errorf("Property failed: %v", err)
	}
}

// TestGeolocationDataAvailability tests that geolocation data is properly structured
func TestGeolocationDataAvailability(t *testing.T) {
	// Test that infrastructure info can hold geolocation data
	infraInfo := InfrastructureInfo{
		HostingProvider: "Amazon Web Services",
		CloudPlatform:   "AWS",
		DataCenter:      "us-east-1, Virginia, US",
		NetworkInfo: NetworkInfo{
			ASN:          "AS16509",
			Organization: "Amazon.com, Inc.",
		},
	}

	// Verify all fields are accessible
	if infraInfo.HostingProvider == "" {
		t.Error("HostingProvider should be accessible")
	}
	if infraInfo.CloudPlatform == "" {
		t.Error("CloudPlatform should be accessible")
	}
	if infraInfo.DataCenter == "" {
		t.Error("DataCenter should be accessible")
	}
	if infraInfo.NetworkInfo.ASN == "" {
		t.Error("ASN should be accessible")
	}
	if infraInfo.NetworkInfo.Organization == "" {
		t.Error("Organization should be accessible")
	}
}