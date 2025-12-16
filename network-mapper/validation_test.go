package networkmapper

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Test ValidateScanResult function
func TestValidateScanResult(t *testing.T) {
	t.Run("valid scan result", func(t *testing.T) {
		result := generateValidScanResult()
		err := ValidateScanResult(&result)
		require.NoError(t, err, "Valid scan result should pass validation")
	})

	t.Run("nil scan result", func(t *testing.T) {
		err := ValidateScanResult(nil)
		require.Error(t, err, "Nil scan result should fail validation")
		require.Contains(t, err.Error(), "scan result cannot be nil")
	})

	t.Run("zero timestamp", func(t *testing.T) {
		result := generateValidScanResult()
		result.Timestamp = time.Time{}
		err := ValidateScanResult(&result)
		require.Error(t, err, "Zero timestamp should fail validation")
		require.Contains(t, err.Error(), "valid timestamp")
	})

	t.Run("empty hosts", func(t *testing.T) {
		result := generateValidScanResult()
		result.Hosts = []HostResult{}
		err := ValidateScanResult(&result)
		require.Error(t, err, "Empty hosts should fail validation")
		require.Contains(t, err.Error(), "at least one host result")
	})
}

// Test ValidateHostResult function
func TestValidateHostResult(t *testing.T) {
	t.Run("valid host result", func(t *testing.T) {
		host := generateValidHostResult()
		err := ValidateHostResult(host, 0)
		require.NoError(t, err, "Valid host result should pass validation")
	})

	t.Run("empty target", func(t *testing.T) {
		host := generateValidHostResult()
		host.Target = ""
		err := ValidateHostResult(host, 0)
		require.Error(t, err, "Empty target should fail validation")
		require.Contains(t, err.Error(), "target cannot be empty")
	})

	t.Run("invalid host status", func(t *testing.T) {
		host := generateValidHostResult()
		host.Status = HostStatus(99) // Invalid status
		err := ValidateHostResult(host, 0)
		require.Error(t, err, "Invalid host status should fail validation")
		require.Contains(t, err.Error(), "status must be up, down, or unknown")
	})

	t.Run("negative response time", func(t *testing.T) {
		host := generateValidHostResult()
		host.ResponseTime = -1 * time.Second
		err := ValidateHostResult(host, 0)
		require.Error(t, err, "Negative response time should fail validation")
		require.Contains(t, err.Error(), "response time cannot be negative")
	})
}

// Test ValidatePortResult function
func TestValidatePortResult(t *testing.T) {
	t.Run("valid port result", func(t *testing.T) {
		port := generateValidPortResult()
		err := ValidatePortResult(port, 0, 0)
		require.NoError(t, err, "Valid port result should pass validation")
	})

	t.Run("invalid port number - too low", func(t *testing.T) {
		port := generateValidPortResult()
		port.Port = 0
		err := ValidatePortResult(port, 0, 0)
		require.Error(t, err, "Port 0 should fail validation")
		require.Contains(t, err.Error(), "port number must be between 1 and 65535")
	})

	t.Run("invalid port number - too high", func(t *testing.T) {
		port := generateValidPortResult()
		port.Port = 65536
		err := ValidatePortResult(port, 0, 0)
		require.Error(t, err, "Port 65536 should fail validation")
		require.Contains(t, err.Error(), "port number must be between 1 and 65535")
	})

	t.Run("empty protocol", func(t *testing.T) {
		port := generateValidPortResult()
		port.Protocol = ""
		err := ValidatePortResult(port, 0, 0)
		require.Error(t, err, "Empty protocol should fail validation")
		require.Contains(t, err.Error(), "protocol cannot be empty")
	})

	t.Run("invalid protocol", func(t *testing.T) {
		port := generateValidPortResult()
		port.Protocol = "invalid"
		err := ValidatePortResult(port, 0, 0)
		require.Error(t, err, "Invalid protocol should fail validation")
		require.Contains(t, err.Error(), "protocol must be 'tcp' or 'udp'")
	})

	t.Run("invalid port state", func(t *testing.T) {
		port := generateValidPortResult()
		port.State = PortState(99) // Invalid state
		err := ValidatePortResult(port, 0, 0)
		require.Error(t, err, "Invalid port state should fail validation")
		require.Contains(t, err.Error(), "port state must be open, closed, or filtered")
	})

	t.Run("negative response time", func(t *testing.T) {
		port := generateValidPortResult()
		port.ResponseTime = -1 * time.Millisecond
		err := ValidatePortResult(port, 0, 0)
		require.Error(t, err, "Negative response time should fail validation")
		require.Contains(t, err.Error(), "response time cannot be negative")
	})
}

// Test ValidateServiceInfo function
func TestValidateServiceInfo(t *testing.T) {
	t.Run("valid service info", func(t *testing.T) {
		service := generateValidServiceInfo()
		err := ValidateServiceInfo(service, 0, 0)
		require.NoError(t, err, "Valid service info should pass validation")
	})

	t.Run("invalid confidence - too low", func(t *testing.T) {
		service := generateValidServiceInfo()
		service.Confidence = -1
		err := ValidateServiceInfo(service, 0, 0)
		require.Error(t, err, "Negative confidence should fail validation")
		require.Contains(t, err.Error(), "confidence must be between 0 and 100")
	})

	t.Run("invalid confidence - too high", func(t *testing.T) {
		service := generateValidServiceInfo()
		service.Confidence = 101
		err := ValidateServiceInfo(service, 0, 0)
		require.Error(t, err, "Confidence > 100 should fail validation")
		require.Contains(t, err.Error(), "confidence must be between 0 and 100")
	})

	t.Run("empty service name with other details", func(t *testing.T) {
		service := ServiceInfo{
			Name:       "",
			Version:    "1.0",
			Confidence: 50,
		}
		err := ValidateServiceInfo(service, 0, 0)
		require.Error(t, err, "Empty service name with other details should fail validation")
		require.Contains(t, err.Error(), "service name cannot be empty")
	})

	t.Run("empty extra info key", func(t *testing.T) {
		service := generateValidServiceInfo()
		service.ExtraInfo = []KeyValue{{Key: "", Value: "test"}}
		err := ValidateServiceInfo(service, 0, 0)
		require.Error(t, err, "Empty extra info key should fail validation")
		require.Contains(t, err.Error(), "extra info key cannot be empty")
	})
}

// Test ValidateOSInfo function
func TestValidateOSInfo(t *testing.T) {
	t.Run("valid OS info", func(t *testing.T) {
		osInfo := generateValidOSInfo()
		err := ValidateOSInfo(osInfo, 0)
		require.NoError(t, err, "Valid OS info should pass validation")
	})

	t.Run("invalid confidence - too low", func(t *testing.T) {
		osInfo := generateValidOSInfo()
		osInfo.Confidence = -1
		err := ValidateOSInfo(osInfo, 0)
		require.Error(t, err, "Negative confidence should fail validation")
		require.Contains(t, err.Error(), "confidence must be between 0 and 100")
	})

	t.Run("invalid confidence - too high", func(t *testing.T) {
		osInfo := generateValidOSInfo()
		osInfo.Confidence = 101
		err := ValidateOSInfo(osInfo, 0)
		require.Error(t, err, "Confidence > 100 should fail validation")
		require.Contains(t, err.Error(), "confidence must be between 0 and 100")
	})

	t.Run("empty OS match name", func(t *testing.T) {
		osInfo := generateValidOSInfo()
		osInfo.Matches = []OSMatch{{Name: "", Version: "1.0", Confidence: 50}}
		err := ValidateOSInfo(osInfo, 0)
		require.Error(t, err, "Empty OS match name should fail validation")
		require.Contains(t, err.Error(), "OS match name cannot be empty")
	})

	t.Run("invalid OS match confidence", func(t *testing.T) {
		osInfo := generateValidOSInfo()
		osInfo.Matches = []OSMatch{{Name: "Linux", Version: "1.0", Confidence: 101}}
		err := ValidateOSInfo(osInfo, 0)
		require.Error(t, err, "Invalid OS match confidence should fail validation")
		require.Contains(t, err.Error(), "OS match confidence must be between 0 and 100")
	})
}

// Test GenerateScanResultSummary function
func TestGenerateScanResultSummary(t *testing.T) {
	t.Run("valid scan result", func(t *testing.T) {
		result := generateValidScanResult()
		summary, err := GenerateScanResultSummary(&result)
		require.NoError(t, err, "Valid scan result should generate summary")
		require.NotNil(t, summary, "Summary should not be nil")

		// Verify summary contains expected data
		require.Equal(t, result.Timestamp, summary.Timestamp)
		require.Equal(t, len(result.Hosts), summary.TotalHosts)
		require.Equal(t, result.Statistics.OpenPorts, summary.OpenPorts)
		require.Equal(t, result.Statistics.ClosedPorts, summary.ClosedPorts)
		require.Equal(t, result.Statistics.FilteredPorts, summary.FilteredPorts)
	})

	t.Run("nil scan result", func(t *testing.T) {
		summary, err := GenerateScanResultSummary(nil)
		require.Error(t, err, "Nil scan result should fail")
		require.Nil(t, summary, "Summary should be nil on error")
		require.Contains(t, err.Error(), "scan result cannot be nil")
	})

	t.Run("invalid scan result", func(t *testing.T) {
		result := generateValidScanResult()
		result.Hosts = []HostResult{} // Make it invalid
		summary, err := GenerateScanResultSummary(&result)
		require.Error(t, err, "Invalid scan result should fail")
		require.Nil(t, summary, "Summary should be nil on error")
		require.Contains(t, err.Error(), "scan result validation failed")
	})
}

// Helper functions to generate valid test data

func generateValidScanResult() ScanResult {
	return ScanResult{
		Timestamp: time.Now(),
		ScanConfig: ScanConfig{
			Targets:       []string{"192.168.1.1"},
			Ports:         []int{80, 443},
			ScanType:      ScanTypeTCPConnect,
			ServiceDetect: true,
			OSDetect:      true,
			MaxThreads:    10,
			Timeout:       5 * time.Second,
			OutputFormat:  OutputFormatJSON,
		},
		Hosts: []HostResult{
			generateValidHostResult(),
		},
		Statistics: ScanStatistics{
			HostsScanned:  1,
			HostsTotal:    1,
			PortsScanned:  2,
			PortsTotal:    2,
			OpenPorts:     1,
			ClosedPorts:   1,
			FilteredPorts: 0,
			StartTime:     time.Now().Add(-time.Hour),
			EndTime:       time.Now(),
			ElapsedTime:   time.Hour,
			ScanRate:      2.0,
		},
	}
}

func generateValidHostResult() HostResult {
	return HostResult{
		Target:       "192.168.1.1",
		Status:       HostUp,
		ResponseTime: 100 * time.Millisecond,
		Ports: []PortResult{
			{
				Port:         80,
				Protocol:     "tcp",
				State:        PortOpen,
				Service:      generateValidServiceInfo(),
				ResponseTime: 50 * time.Millisecond,
			},
			{
				Port:         443,
				Protocol:     "tcp",
				State:        PortClosed,
				ResponseTime: 75 * time.Millisecond,
			},
		},
		OS: generateValidOSInfo(),
	}
}

func generateValidPortResult() PortResult {
	return PortResult{
		Port:         80,
		Protocol:     "tcp",
		State:        PortOpen,
		Service:      generateValidServiceInfo(),
		ResponseTime: 50 * time.Millisecond,
	}
}

func generateValidServiceInfo() ServiceInfo {
	return ServiceInfo{
		Name:       "http",
		Version:    "1.1",
		Product:    "Apache",
		Confidence: 85.5,
		ExtraInfo:  []KeyValue{{Key: "server", Value: "Apache/2.4.41"}},
	}
}

func generateValidOSInfo() OSInfo {
	return OSInfo{
		Family:     "Linux",
		Version:    "Ubuntu 20.04",
		Confidence: 90.0,
		Matches: []OSMatch{
			{
				Name:       "Linux Ubuntu 20.04",
				Version:    "20.04",
				Confidence: 90.0,
			},
		},
	}
}
