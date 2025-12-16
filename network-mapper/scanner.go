package networkmapper

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

// DefaultPortScanner implements the PortScanner interface
type DefaultPortScanner struct {
	timeout      time.Duration
	maxRetries   int
	logger       *log.Logger
	nmLogger     *NetworkMapperLogger
	errorHandler *ErrorHandler
}

// NewDefaultPortScanner creates a new DefaultPortScanner with default settings
func NewDefaultPortScanner(timeout time.Duration, maxRetries int, logger *log.Logger) *DefaultPortScanner {
	if logger == nil {
		logger = log.Default()
	}
	return &DefaultPortScanner{
		timeout:    timeout,
		maxRetries: maxRetries,
		logger:     logger,
	}
}

// NewDefaultPortScannerWithErrorHandling creates a new DefaultPortScanner with comprehensive error handling
func NewDefaultPortScannerWithErrorHandling(timeout time.Duration, maxRetries int, logger *NetworkMapperLogger, errorHandler *ErrorHandler) *DefaultPortScanner {
	if logger == nil {
		logger = NewNetworkMapperLogger("port-scanner", LogLevelInfo)
	}
	if errorHandler == nil {
		errorHandler = NewErrorHandler(logger, nil)
	}

	return &DefaultPortScanner{
		timeout:      timeout,
		maxRetries:   maxRetries,
		logger:       logger.ToStandardLogger(),
		nmLogger:     logger,
		errorHandler: errorHandler,
	}
}

// ScanPort scans a single port on a target using the specified scan type
func (ps *DefaultPortScanner) ScanPort(ctx context.Context, target string, port int, scanType ScanType) PortResult {
	// Validate port range (Requirements 1.5, 2.5)
	if !isValidPort(port) {
		validationErr := NewValidationError("port_scan", fmt.Sprintf("port %d is not valid (must be 1-65535)", port))
		if ps.errorHandler != nil {
			ps.errorHandler.HandleValidationError(validationErr, "port_scan")
		} else {
			ps.logger.Printf("Invalid port %d for target %s", port, target)
		}
		return PortResult{
			Port:     port,
			Protocol: getProtocolForScanType(scanType),
			State:    PortFiltered,
		}
	}

	startTime := time.Now()

	// Use comprehensive error handling if available
	if ps.errorHandler != nil {
		return ps.scanPortWithErrorHandling(ctx, target, port, scanType, startTime)
	}

	// Fallback to basic error handling for backward compatibility
	return ps.scanPortBasic(ctx, target, port, scanType, startTime)
}

// scanPortWithErrorHandling performs port scanning with comprehensive error handling
func (ps *DefaultPortScanner) scanPortWithErrorHandling(ctx context.Context, target string, port int, scanType ScanType, startTime time.Time) PortResult {
	var result PortResult

	// Use error handler's retry mechanism
	err := ps.errorHandler.HandleNetworkOperation(ctx, "port_scan", target, port, func() error {
		state, scanErr := ps.scanPortWithType(ctx, target, port, scanType)
		if scanErr != nil {
			return scanErr
		}

		responseTime := time.Since(startTime)
		if responseTime == 0 {
			responseTime = 1 * time.Microsecond // Ensure non-zero response time
		}

		result = PortResult{
			Port:         port,
			Protocol:     getProtocolForScanType(scanType),
			State:        state,
			ResponseTime: responseTime,
		}

		// Log successful scan result
		if ps.nmLogger != nil {
			ps.nmLogger.LogPortScanResult(target, result)
		}

		return nil
	})

	// If error handling failed, return filtered result
	if err != nil {
		responseTime := time.Since(startTime)
		if responseTime == 0 {
			responseTime = 1 * time.Microsecond
		}

		return PortResult{
			Port:         port,
			Protocol:     getProtocolForScanType(scanType),
			State:        PortFiltered,
			ResponseTime: responseTime,
		}
	}

	return result
}

// scanPortBasic performs port scanning with basic error handling (backward compatibility)
func (ps *DefaultPortScanner) scanPortBasic(ctx context.Context, target string, port int, scanType ScanType, startTime time.Time) PortResult {
	var state PortState
	var err error

	// Retry logic for network errors (Requirements 1.5, 2.5)
	for attempt := 0; attempt <= ps.maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			ps.logger.Printf("Scan cancelled for %s:%d", target, port)
			responseTime := time.Since(startTime)
			if responseTime == 0 {
				responseTime = 1 * time.Microsecond // Ensure non-zero response time
			}
			return PortResult{
				Port:         port,
				Protocol:     getProtocolForScanType(scanType),
				State:        PortFiltered,
				ResponseTime: responseTime,
			}
		default:
		}

		state, err = ps.scanPortWithType(ctx, target, port, scanType)
		if err == nil {
			break
		}

		if attempt < ps.maxRetries {
			ps.logger.Printf("Scan attempt %d failed for %s:%d: %v, retrying...", attempt+1, target, port, err)
			// Small delay before retry
			time.Sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
		} else {
			ps.logger.Printf("All scan attempts failed for %s:%d: %v", target, port, err)
			state = PortFiltered // Assume filtered if we can't determine state
		}
	}

	responseTime := time.Since(startTime)
	if responseTime == 0 {
		responseTime = 1 * time.Microsecond // Ensure non-zero response time
	}

	result := PortResult{
		Port:         port,
		Protocol:     getProtocolForScanType(scanType),
		State:        state,
		ResponseTime: responseTime,
	}

	return result
}

// ScanPorts scans multiple ports on a target using the specified scan type
func (ps *DefaultPortScanner) ScanPorts(ctx context.Context, target string, ports []int, scanType ScanType) []PortResult {
	results := make([]PortResult, len(ports))
	var wg sync.WaitGroup

	// Use a semaphore to limit concurrent connections
	semaphore := make(chan struct{}, 50) // Limit to 50 concurrent scans per target

	for i, port := range ports {
		wg.Add(1)
		go func(index, p int) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			results[index] = ps.ScanPort(ctx, target, p, scanType)
		}(i, port)
	}

	wg.Wait()
	return results
}

// scanPortWithType performs the actual port scan based on scan type
func (ps *DefaultPortScanner) scanPortWithType(ctx context.Context, target string, port int, scanType ScanType) (PortState, error) {
	switch scanType {
	case ScanTypeTCPConnect:
		return ps.tcpConnectScan(ctx, target, port)
	case ScanTypeTCPSYN:
		// For now, fall back to TCP Connect scan as SYN scan requires raw sockets
		// TODO: Implement proper SYN scan with raw sockets in future iteration
		ps.logger.Printf("SYN scan not yet implemented, falling back to TCP Connect for %s:%d", target, port)
		return ps.tcpConnectScan(ctx, target, port)
	case ScanTypeUDP:
		return ps.udpScan(ctx, target, port)
	default:
		return PortFiltered, fmt.Errorf("unsupported scan type: %v", scanType)
	}
}

// tcpConnectScan performs a TCP Connect scan (Requirements 5.2)
func (ps *DefaultPortScanner) tcpConnectScan(ctx context.Context, target string, port int) (PortState, error) {
	address := net.JoinHostPort(target, strconv.Itoa(port))

	// Create a dialer with timeout
	dialer := &net.Dialer{
		Timeout: ps.timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		// Check if it's a connection refused (port closed) vs other errors
		if netErr, ok := err.(net.Error); ok {
			if netErr.Timeout() {
				return PortFiltered, err
			}
		}
		// Connection refused typically means port is closed
		return PortClosed, nil
	}

	conn.Close()
	return PortOpen, nil
}

// udpScan performs a UDP scan with protocol-specific probes (Requirements 5.3)
func (ps *DefaultPortScanner) udpScan(ctx context.Context, target string, port int) (PortState, error) {
	address := net.JoinHostPort(target, strconv.Itoa(port))

	// Create UDP connection with timeout
	conn, err := net.DialTimeout("udp", address, ps.timeout)
	if err != nil {
		return PortFiltered, err
	}
	defer conn.Close()

	// Send protocol-specific probe based on port
	probe := getUDPProbe(port)

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(ps.timeout))

	// Send probe
	_, err = conn.Write(probe)
	if err != nil {
		return PortFiltered, err
	}

	// Try to read response
	buffer := make([]byte, 1024)
	_, err = conn.Read(buffer)

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// No response could mean open or filtered
			return PortOpen, nil // Assume open for UDP if no ICMP unreachable
		}
		return PortFiltered, err
	}

	// Got a response, port is definitely open
	return PortOpen, nil
}

// isValidPort validates that a port number is in the valid range (1-65535)
func isValidPort(port int) bool {
	return port >= 1 && port <= 65535
}

// getProtocolForScanType returns the protocol string for a scan type
func getProtocolForScanType(scanType ScanType) string {
	switch scanType {
	case ScanTypeTCPConnect, ScanTypeTCPSYN:
		return "tcp"
	case ScanTypeUDP:
		return "udp"
	default:
		return "unknown"
	}
}

// getUDPProbe returns a protocol-specific probe for UDP scanning
func getUDPProbe(port int) []byte {
	switch port {
	case 53: // DNS
		// DNS query for "example.com"
		return []byte{
			0x12, 0x34, // Transaction ID
			0x01, 0x00, // Flags: standard query
			0x00, 0x01, // Questions: 1
			0x00, 0x00, // Answer RRs: 0
			0x00, 0x00, // Authority RRs: 0
			0x00, 0x00, // Additional RRs: 0
			// Query: example.com
			0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
			0x03, 'c', 'o', 'm',
			0x00,       // End of name
			0x00, 0x01, // Type: A
			0x00, 0x01, // Class: IN
		}
	case 123: // NTP
		// NTP request packet
		return []byte{
			0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}
	case 161: // SNMP
		// SNMP GetRequest
		return []byte{
			0x30, 0x26, // SEQUENCE, length 38
			0x02, 0x01, 0x00, // INTEGER version (0 = v1)
			0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', // OCTET STRING community
			0xa0, 0x19, // GetRequest PDU
			0x02, 0x01, 0x01, // INTEGER request-id
			0x02, 0x01, 0x00, // INTEGER error-status
			0x02, 0x01, 0x00, // INTEGER error-index
			0x30, 0x0e, // SEQUENCE variable-bindings
			0x30, 0x0c, // SEQUENCE
			0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID
			0x05, 0x00, // NULL
		}
	default:
		// Generic UDP probe - empty packet
		return []byte{}
	}
}
