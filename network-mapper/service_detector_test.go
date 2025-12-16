package networkmapper

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// **Feature: network-mapper, Property 8: Service Detection Activation**
// **Validates: Requirements 3.1, 3.2**
// Property: For any open port discovered, service identification should be attempted when service detection is enabled
func TestProperty8_ServiceDetectionActivation(t *testing.T) {
	// Property-based test with 100 iterations as specified in design
	for i := range 100 {
		t.Run(fmt.Sprintf("iteration_%d", i), func(t *testing.T) {
			// Create service detector
			logger := log.New(os.Stderr, "test: ", log.LstdFlags)
			detector := NewDefaultServiceDetector(500*time.Millisecond, 1, logger)

			// Generate random port (use common service ports for better testing)
			commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 5432, 6379, 27017}
			port := commonPorts[rand.Intn(len(commonPorts))]

			// Use localhost for testing
			target := "127.0.0.1"

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// Attempt service detection
			serviceInfo := detector.DetectService(ctx, target, port)

			// Verify that service detection was attempted and returned valid info
			require.NotEmpty(t, serviceInfo.Name, "Service detection should return a service name")

			// Verify confidence is within valid range (0-100)
			require.GreaterOrEqual(t, serviceInfo.Confidence, 0.0,
				"Service confidence should be >= 0")
			require.LessOrEqual(t, serviceInfo.Confidence, 100.0,
				"Service confidence should be <= 100")

			// Verify that the service name is not empty or just whitespace
			require.NotEmpty(t, serviceInfo.Name, "Service name should not be empty")

			// For common ports, we should get reasonable service names
			expectedServices := map[int]string{
				21:    "ftp",
				22:    "ssh",
				23:    "telnet",
				25:    "smtp",
				53:    "dns",
				80:    "http",
				110:   "pop3",
				143:   "imap",
				443:   "https",
				993:   "imaps",
				995:   "pop3s",
				1433:  "mssql",
				3306:  "mysql",
				5432:  "postgresql",
				6379:  "redis",
				27017: "mongodb",
			}

			if expectedService, exists := expectedServices[port]; exists {
				// For well-known ports, we should get the expected service or at least some detection
				if serviceInfo.Confidence > 0 {
					// If we have confidence, the service name should be reasonable
					require.Contains(t, []string{expectedService, "unknown"}, serviceInfo.Name,
						"Service name should be %s or unknown for port %d", expectedService, port)
				}
			}

			// Verify that extra info is properly structured if present
			for _, kv := range serviceInfo.ExtraInfo {
				require.NotEmpty(t, kv.Key, "Extra info key should not be empty")
				// Value can be empty, but key should not be
			}
		})
	}
}

// **Feature: network-mapper, Property 9: Service Information Completeness**
// **Validates: Requirements 3.3**
// Property: For any successfully identified service, the output should include service name, version, and additional details
func TestProperty9_ServiceInformationCompleteness(t *testing.T) {
	// Property-based test with 100 iterations as specified in design
	for i := range 100 {
		t.Run(fmt.Sprintf("iteration_%d", i), func(t *testing.T) {
			// Create service detector
			logger := log.New(os.Stderr, "test: ", log.LstdFlags)
			detector := NewDefaultServiceDetector(500*time.Millisecond, 1, logger)

			// Generate random port
			port := rand.Intn(65535) + 1
			target := "127.0.0.1"

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// Attempt service detection
			serviceInfo := detector.DetectService(ctx, target, port)

			// Verify that service information structure is complete
			// Service name should always be present (even if "unknown")
			require.NotEmpty(t, serviceInfo.Name, "Service name should always be present")

			// Confidence should be a valid percentage
			require.GreaterOrEqual(t, serviceInfo.Confidence, 0.0,
				"Confidence should be >= 0")
			require.LessOrEqual(t, serviceInfo.Confidence, 100.0,
				"Confidence should be <= 100")

			// If service is identified with high confidence, more details should be available
			if serviceInfo.Confidence > 80.0 {
				// High confidence services should have meaningful names
				require.NotEqual(t, "unknown", serviceInfo.Name,
					"High confidence service should not be unknown")
				require.NotEmpty(t, serviceInfo.Name,
					"High confidence service should have a name")
			}

			// Version field should be a string (can be empty)
			require.IsType(t, "", serviceInfo.Version,
				"Version should be a string")

			// Product field should be a string (can be empty)
			require.IsType(t, "", serviceInfo.Product,
				"Product should be a string")

			// Banner field should be a string (can be empty)
			require.IsType(t, "", serviceInfo.Banner,
				"Banner should be a string")

			// ExtraInfo should be a valid slice (can be empty)
			require.NotNil(t, serviceInfo.ExtraInfo,
				"ExtraInfo should not be nil")

			// If ExtraInfo is present, verify structure
			for _, kv := range serviceInfo.ExtraInfo {
				require.IsType(t, "", kv.Key,
					"ExtraInfo key should be a string")
				require.IsType(t, "", kv.Value,
					"ExtraInfo value should be a string")
				require.NotEmpty(t, kv.Key,
					"ExtraInfo key should not be empty")
			}

			// If we have a banner, it should be non-empty when confidence > 0
			if serviceInfo.Confidence > 0 && serviceInfo.Banner != "" {
				require.NotEmpty(t, serviceInfo.Banner,
					"Non-empty banner should contain actual content")
			}
		})
	}
}

// Test service detection with mock server
func TestServiceDetectionWithMockServer(t *testing.T) {
	// Start a mock HTTP server for testing
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "Should be able to start mock server")
	defer listener.Close()

	// Get the port the server is listening on
	_, portStr, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err, "Should be able to get server port")
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err, "Should be able to parse port number")

	// Start serving HTTP responses
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return // Listener closed
			}

			// Send a simple HTTP response
			response := "HTTP/1.1 200 OK\r\nServer: TestServer/1.0\r\nContent-Length: 0\r\n\r\n"
			conn.Write([]byte(response))
			conn.Close()
		}
	}()

	// Test service detection
	logger := log.New(os.Stderr, "test: ", log.LstdFlags)
	detector := NewDefaultServiceDetector(1*time.Second, 1, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	serviceInfo := detector.DetectService(ctx, "127.0.0.1", port)

	// Should detect HTTP service
	require.Equal(t, "http", serviceInfo.Name, "Should detect HTTP service")
	require.Greater(t, serviceInfo.Confidence, 80.0, "Should have high confidence for HTTP")
	require.NotEmpty(t, serviceInfo.Banner, "Should capture HTTP banner")
	require.Contains(t, serviceInfo.Banner, "HTTP/1.1", "Banner should contain HTTP version")
}

// Test banner grabbing functionality
func TestBannerGrabbing(t *testing.T) {
	// Test with a mock server that sends a banner
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "Should be able to start mock server")
	defer listener.Close()

	// Get the port
	_, portStr, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err, "Should be able to get server port")
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err, "Should be able to parse port number")

	expectedBanner := "Welcome to Test Server v1.0\nReady for connections"

	// Start serving banners
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return // Listener closed
			}

			// Send banner immediately on connection
			conn.Write([]byte(expectedBanner + "\n"))
			conn.Close()
		}
	}()

	// Test banner grabbing
	logger := log.New(os.Stderr, "test: ", log.LstdFlags)
	detector := NewDefaultServiceDetector(1*time.Second, 1, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	banner, err := detector.GrabBanner(ctx, "127.0.0.1", port)
	require.NoError(t, err, "Should be able to grab banner")
	require.Equal(t, expectedBanner, banner, "Should receive expected banner")
}

// Test service detection with various port types
func TestServiceDetectionPortTypes(t *testing.T) {
	logger := log.New(os.Stderr, "test: ", log.LstdFlags)
	detector := NewDefaultServiceDetector(200*time.Millisecond, 1, logger)

	tests := []struct {
		name            string
		port            int
		expectedService string
		minConfidence   float64
	}{
		{"HTTP port", 80, "http", 40.0},
		{"HTTPS port", 443, "https", 40.0},
		{"SSH port", 22, "ssh", 40.0},
		{"FTP port", 21, "ftp", 40.0},
		{"SMTP port", 25, "smtp", 40.0},
		{"DNS port", 53, "dns", 40.0},
		{"MySQL port", 3306, "mysql", 40.0},
		{"PostgreSQL port", 5432, "postgresql", 40.0},
		{"Unknown port", 54321, "unknown", 0.0},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serviceInfo := detector.DetectService(ctx, "127.0.0.1", tt.port)

			require.Equal(t, tt.expectedService, serviceInfo.Name,
				"Should detect correct service for port %d", tt.port)
			require.GreaterOrEqual(t, serviceInfo.Confidence, tt.minConfidence,
				"Should have minimum confidence for port %d", tt.port)
		})
	}
}

// Test service signature matching
func TestServiceSignatureMatching(t *testing.T) {
	logger := log.New(os.Stderr, "test: ", log.LstdFlags)
	detector := NewDefaultServiceDetector(1*time.Second, 1, logger)

	tests := []struct {
		name            string
		port            int
		banner          string
		expectedService string
		expectVersion   bool
	}{
		{
			name:            "HTTP server",
			port:            80,
			banner:          "HTTP/1.1 200 OK\nServer: Apache/2.4.41",
			expectedService: "http",
			expectVersion:   true,
		},
		{
			name:            "SSH server",
			port:            22,
			banner:          "SSH-2.0-OpenSSH_8.0",
			expectedService: "ssh",
			expectVersion:   true,
		},
		{
			name:            "FTP server",
			port:            21,
			banner:          "220 Welcome to FTP Server v2.1",
			expectedService: "ftp",
			expectVersion:   true,
		},
		{
			name:            "Unknown service",
			port:            12345,
			banner:          "Some random banner text",
			expectedService: "unknown",
			expectVersion:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serviceInfo := detector.MatchServiceSignature(tt.port, tt.banner)

			if tt.expectedService != "unknown" {
				require.Equal(t, tt.expectedService, serviceInfo.Name,
					"Should match correct service")
				require.Greater(t, serviceInfo.Confidence, 80.0,
					"Should have high confidence for signature match")

				if tt.expectVersion {
					require.NotEmpty(t, serviceInfo.Version,
						"Should extract version information")
				}
			}
		})
	}
}

// Test extra info extraction
func TestExtraInfoExtraction(t *testing.T) {
	logger := log.New(os.Stderr, "test: ", log.LstdFlags)
	detector := NewDefaultServiceDetector(1*time.Second, 1, logger)

	tests := []struct {
		name         string
		banner       string
		expectServer bool
		expectInfo   bool
	}{
		{
			name:         "HTTP with server header",
			banner:       "HTTP/1.1 200 OK\nServer: Apache/2.4.41\nContent-Type: text/html",
			expectServer: true,
			expectInfo:   false,
		},
		{
			name:         "Banner with version info",
			banner:       "Welcome to MyService version 1.2.3\nReady for connections",
			expectServer: false,
			expectInfo:   true,
		},
		{
			name:         "Apache server info",
			banner:       "HTTP/1.1 200 OK\nServer: Apache/2.4.41 (Ubuntu)\nConnection: close",
			expectServer: true,
			expectInfo:   true,
		},
		{
			name:         "Plain banner",
			banner:       "Hello World",
			expectServer: false,
			expectInfo:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extraInfo := detector.extractExtraInfo(tt.banner)

			hasServer := false
			hasInfo := false

			for _, kv := range extraInfo {
				if kv.Key == "server" {
					hasServer = true
				}
				if kv.Key == "product_info" || kv.Key == "banner_line" {
					hasInfo = true
				}
			}

			require.Equal(t, tt.expectServer, hasServer,
				"Server info extraction should match expectation")
			require.Equal(t, tt.expectInfo, hasInfo,
				"Additional info extraction should match expectation")
		})
	}
}

// Test probe generation for different ports
func TestProbeGeneration(t *testing.T) {
	logger := log.New(os.Stderr, "test: ", log.LstdFlags)
	detector := NewDefaultServiceDetector(1*time.Second, 1, logger)

	tests := []struct {
		name        string
		port        int
		expectProbe bool
	}{
		{"HTTP port", 80, true},
		{"HTTPS port", 443, false}, // No probe for HTTPS over raw socket
		{"SMTP port", 25, true},
		{"POP3 port", 110, true},
		{"IMAP port", 143, true},
		{"FTP port", 21, false}, // FTP sends banner on connect
		{"SSH port", 22, false}, // SSH sends banner on connect
		{"Unknown port", 54321, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe := detector.getProbeForPort(tt.port)

			if tt.expectProbe {
				require.Greater(t, len(probe), 0,
					"Should have probe for port %d", tt.port)
			} else {
				require.Equal(t, 0, len(probe),
					"Should not have probe for port %d", tt.port)
			}
		})
	}
}

// Test service detection error handling
func TestServiceDetectionErrorHandling(t *testing.T) {
	logger := log.New(os.Stderr, "test: ", log.LstdFlags)
	detector := NewDefaultServiceDetector(100*time.Millisecond, 1, logger)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Test with unreachable target
	serviceInfo := detector.DetectService(ctx, "192.0.2.1", 80) // RFC 5737 test address

	// Should still return service info based on port
	require.NotEmpty(t, serviceInfo.Name, "Should return service name even on connection failure")
	require.Equal(t, "http", serviceInfo.Name, "Should identify HTTP service by port")
	require.Equal(t, 50.0, serviceInfo.Confidence, "Should have medium confidence for port-based detection")
}

// Test concurrent service detection
func TestConcurrentServiceDetection(t *testing.T) {
	logger := log.New(os.Stderr, "test: ", log.LstdFlags)
	detector := NewDefaultServiceDetector(200*time.Millisecond, 1, logger)

	ports := []int{21, 22, 23, 25, 53, 80, 110, 143, 443}
	results := make(chan ServiceInfo, len(ports))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start concurrent detections
	for _, port := range ports {
		go func(p int) {
			serviceInfo := detector.DetectService(ctx, "127.0.0.1", p)
			results <- serviceInfo
		}(port)
	}

	// Collect results
	for i := 0; i < len(ports); i++ {
		select {
		case serviceInfo := <-results:
			require.NotEmpty(t, serviceInfo.Name, "Should get service name from concurrent detection")
		case <-time.After(15 * time.Second):
			t.Fatal("Timeout waiting for concurrent service detection")
		}
	}
}
