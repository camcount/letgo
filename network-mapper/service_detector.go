package networkmapper

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// DefaultServiceDetector implements the ServiceDetector interface
type DefaultServiceDetector struct {
	timeout    time.Duration
	maxRetries int
	logger     *log.Logger
	signatures []ServiceSignature
}

// NewDefaultServiceDetector creates a new DefaultServiceDetector with default settings
func NewDefaultServiceDetector(timeout time.Duration, maxRetries int, logger *log.Logger) *DefaultServiceDetector {
	if logger == nil {
		logger = log.Default()
	}

	detector := &DefaultServiceDetector{
		timeout:    timeout,
		maxRetries: maxRetries,
		logger:     logger,
		signatures: getDefaultServiceSignatures(),
	}

	return detector
}

// DetectService attempts to identify the service running on a port (Requirements 3.1, 3.2)
func (sd *DefaultServiceDetector) DetectService(ctx context.Context, target string, port int) ServiceInfo {
	// First try to grab a banner
	banner, err := sd.GrabBanner(ctx, target, port)
	if err != nil {
		sd.logger.Printf("Failed to grab banner from %s:%d: %v", target, port, err)
		// Return basic service info based on port number
		return sd.getServiceByPort(port)
	}

	// Try to match the banner against known service signatures
	serviceInfo := sd.MatchServiceSignature(port, banner)
	if serviceInfo.Name != "" {
		serviceInfo.Banner = banner
		return serviceInfo
	}

	// If no signature match, return basic info with banner
	basicInfo := sd.getServiceByPort(port)
	basicInfo.Banner = banner
	return basicInfo
}

// GrabBanner attempts to grab a service banner from a port (Requirements 3.2, 3.5)
func (sd *DefaultServiceDetector) GrabBanner(ctx context.Context, target string, port int) (string, error) {
	address := net.JoinHostPort(target, strconv.Itoa(port))

	// Create a dialer with timeout
	dialer := &net.Dialer{
		Timeout: sd.timeout,
	}

	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return "", fmt.Errorf("failed to connect to %s: %w", address, err)
	}
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(sd.timeout))

	// Send protocol-specific probe if available
	probe := sd.getProbeForPort(port)
	if len(probe) > 0 {
		_, err = conn.Write(probe)
		if err != nil {
			return "", fmt.Errorf("failed to send probe to %s: %w", address, err)
		}
	}

	// Read response
	scanner := bufio.NewScanner(conn)
	var lines []string

	// Read up to 10 lines or until timeout
	for i := 0; i < 10 && scanner.Scan(); i++ {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}

	if len(lines) == 0 {
		return "", fmt.Errorf("no banner received from %s", address)
	}

	return strings.Join(lines, "\n"), nil
}

// MatchServiceSignature attempts to match a banner against known service signatures
func (sd *DefaultServiceDetector) MatchServiceSignature(port int, banner string) ServiceInfo {
	for _, sig := range sd.signatures {
		if sig.Port == port || sig.Port == 0 { // 0 means any port
			if sig.Match != "" {
				matched, err := regexp.MatchString(sig.Match, banner)
				if err != nil {
					sd.logger.Printf("Invalid regex pattern %s: %v", sig.Match, err)
					continue
				}

				if matched {
					serviceInfo := ServiceInfo{
						Name:       sig.ServiceName,
						Confidence: 90.0,         // High confidence for regex match
						ExtraInfo:  []KeyValue{}, // Initialize empty slice
					}

					// Extract version if version pattern is provided
					if sig.Version != "" {
						versionRegex, err := regexp.Compile(sig.Version)
						if err == nil {
							matches := versionRegex.FindStringSubmatch(banner)
							if len(matches) > 1 {
								serviceInfo.Version = matches[1]
								serviceInfo.Confidence = 95.0 // Even higher confidence with version
							}
						}
					}

					// Extract additional info from banner
					serviceInfo.ExtraInfo = sd.extractExtraInfo(banner)

					return serviceInfo
				}
			}
		}
	}

	// No signature match found
	return ServiceInfo{
		ExtraInfo: []KeyValue{}, // Initialize empty slice
	}
}

// getServiceByPort returns basic service information based on port number
func (sd *DefaultServiceDetector) getServiceByPort(port int) ServiceInfo {
	commonServices := map[int]string{
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

	if serviceName, exists := commonServices[port]; exists {
		return ServiceInfo{
			Name:       serviceName,
			Confidence: 50.0,         // Medium confidence based on port only
			ExtraInfo:  []KeyValue{}, // Initialize empty slice
		}
	}

	return ServiceInfo{
		Name:       "unknown",
		Confidence: 0.0,
		ExtraInfo:  []KeyValue{}, // Initialize empty slice
	}
}

// getProbeForPort returns a protocol-specific probe for banner grabbing
func (sd *DefaultServiceDetector) getProbeForPort(port int) []byte {
	switch port {
	case 80, 8080, 8000, 8443: // HTTP ports
		return []byte("GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: NetworkMapper/1.0\r\nConnection: close\r\n\r\n")
	case 443: // HTTPS - just connect, don't send HTTP over raw socket
		return []byte{}
	case 21: // FTP - no probe needed, server sends banner on connect
		return []byte{}
	case 22: // SSH - no probe needed, server sends banner on connect
		return []byte{}
	case 25: // SMTP
		return []byte("EHLO localhost\r\n")
	case 110: // POP3
		return []byte("USER test\r\n")
	case 143: // IMAP
		return []byte("A001 CAPABILITY\r\n")
	case 1433: // MSSQL
		return []byte{} // TDS protocol is complex, just try to connect
	case 3306: // MySQL
		return []byte{} // MySQL protocol is complex, just try to connect
	case 5432: // PostgreSQL
		return []byte{} // PostgreSQL protocol is complex, just try to connect
	default:
		return []byte{} // No specific probe, just connect
	}
}

// extractExtraInfo extracts additional information from service banners
func (sd *DefaultServiceDetector) extractExtraInfo(banner string) []KeyValue {
	extraInfo := make([]KeyValue, 0) // Initialize as empty slice, not nil
	hasServerHeader := false

	// Look for common patterns in banners
	lines := strings.Split(banner, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Extract server information
		if strings.Contains(strings.ToLower(line), "server:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				extraInfo = append(extraInfo, KeyValue{
					Key:   "server",
					Value: strings.TrimSpace(parts[1]),
				})
				hasServerHeader = true
			}
		}

		// Extract version information
		if strings.Contains(strings.ToLower(line), "version") {
			extraInfo = append(extraInfo, KeyValue{
				Key:   "banner_line",
				Value: line,
			})
		}
	}

	// Extract product information from server headers that contain additional details (like OS info)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		lowerLine := strings.ToLower(line)

		// Check if this is a server header with additional OS/platform info in parentheses
		if strings.Contains(lowerLine, "server:") &&
			(strings.Contains(lowerLine, "apache") || strings.Contains(lowerLine, "nginx") || strings.Contains(lowerLine, "iis")) &&
			strings.Contains(line, "(") {
			extraInfo = append(extraInfo, KeyValue{
				Key:   "product_info",
				Value: line,
			})
		} else if !hasServerHeader && (strings.Contains(lowerLine, "apache") || strings.Contains(lowerLine, "nginx") || strings.Contains(lowerLine, "iis")) {
			// Extract product info from non-server lines only if we don't have a server header
			extraInfo = append(extraInfo, KeyValue{
				Key:   "product_info",
				Value: line,
			})
		}
	}

	return extraInfo
}

// getDefaultServiceSignatures returns a comprehensive list of service detection signatures
func getDefaultServiceSignatures() []ServiceSignature {
	return []ServiceSignature{
		// HTTP Services
		{
			Port:        80,
			Protocol:    "tcp",
			Match:       `HTTP/\d\.\d`,
			ServiceName: "http",
			Version:     `Server:\s*([^\r\n]+)`,
		},
		{
			Port:        443,
			Protocol:    "tcp",
			Match:       `HTTP/\d\.\d`,
			ServiceName: "https",
			Version:     `Server:\s*([^\r\n]+)`,
		},
		{
			Port:        8080,
			Protocol:    "tcp",
			Match:       `HTTP/\d\.\d`,
			ServiceName: "http-proxy",
			Version:     `Server:\s*([^\r\n]+)`,
		},

		// SSH
		{
			Port:        22,
			Protocol:    "tcp",
			Match:       `SSH-\d\.\d`,
			ServiceName: "ssh",
			Version:     `SSH-\d\.\d-([^\r\n\s]+)`,
		},

		// FTP
		{
			Port:        21,
			Protocol:    "tcp",
			Match:       `220.*FTP`,
			ServiceName: "ftp",
			Version:     `220.*?([^\r\n\s]+\s+FTP[^\r\n]*)`,
		},

		// SMTP
		{
			Port:        25,
			Protocol:    "tcp",
			Match:       `220.*SMTP`,
			ServiceName: "smtp",
			Version:     `220\s+([^\r\n]+)`,
		},

		// Telnet
		{
			Port:        23,
			Protocol:    "tcp",
			Match:       `\xff\xfd|\xff\xfb`,
			ServiceName: "telnet",
		},

		// POP3
		{
			Port:        110,
			Protocol:    "tcp",
			Match:       `\+OK.*POP3`,
			ServiceName: "pop3",
			Version:     `\+OK\s+([^\r\n]+)`,
		},

		// IMAP
		{
			Port:        143,
			Protocol:    "tcp",
			Match:       `\* OK.*IMAP`,
			ServiceName: "imap",
			Version:     `\* OK\s+([^\r\n]+)`,
		},

		// MySQL
		{
			Port:        3306,
			Protocol:    "tcp",
			Match:       `\x00\x00\x00\x0a`,
			ServiceName: "mysql",
		},

		// PostgreSQL
		{
			Port:        5432,
			Protocol:    "tcp",
			Match:       `FATAL|ERROR`,
			ServiceName: "postgresql",
		},

		// Redis
		{
			Port:        6379,
			Protocol:    "tcp",
			Match:       `-ERR|PONG`,
			ServiceName: "redis",
		},

		// MongoDB
		{
			Port:        27017,
			Protocol:    "tcp",
			Match:       `MongoDB`,
			ServiceName: "mongodb",
		},

		// DNS
		{
			Port:        53,
			Protocol:    "tcp",
			Match:       `.*`,
			ServiceName: "dns",
		},

		// HTTPS (SSL/TLS)
		{
			Port:        0, // Any port
			Protocol:    "tcp",
			Match:       `\x16\x03`, // TLS handshake
			ServiceName: "ssl",
		},

		// Generic HTTP response (any port)
		{
			Port:        0, // Any port
			Protocol:    "tcp",
			Match:       `HTTP/\d\.\d`,
			ServiceName: "http",
			Version:     `Server:\s*([^\r\n]+)`,
		},

		// Generic web servers
		{
			Port:        0, // Any port
			Protocol:    "tcp",
			Match:       `Apache|nginx|IIS|lighttpd`,
			ServiceName: "http",
			Version:     `(Apache[^\r\n]*|nginx[^\r\n]*|IIS[^\r\n]*|lighttpd[^\r\n]*)`,
		},
	}
}
