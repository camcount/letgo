package networkmapper

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/letgo/paths"
)

// DefaultResultManager implements the ResultManager interface
type DefaultResultManager struct {
	configManager *ConfigManager
}

// NewResultManager creates a new DefaultResultManager instance
func NewResultManager() ResultManager {
	return &DefaultResultManager{
		configManager: NewConfigManager(),
	}
}

// SaveResults saves scan results to a file in the specified format
// Implements Requirements 6.1, 6.2, 6.3, 6.4, 6.5
func (rm *DefaultResultManager) SaveResults(results *ScanResult, format OutputFormat, filename string) error {
	if results == nil {
		return fmt.Errorf("scan results cannot be nil")
	}

	if filename == "" {
		// Use default path from config manager if not provided
		filename = rm.configManager.GetDefaultResultPath(format)
	} else if !filepath.IsAbs(filename) {
		// If relative path, place it in the results directory
		filename = filepath.Join(rm.configManager.GetResultsDir(), filename)
	}

	// Ensure the directory exists using config manager
	if err := rm.configManager.EnsureDirectories(); err != nil {
		return fmt.Errorf("failed to ensure directories: %w", err)
	}

	// Export results to bytes
	data, err := rm.ExportResults(results, format)
	if err != nil {
		return fmt.Errorf("failed to export results: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write results to file %s: %w", filename, err)
	}

	return nil
}

// ExportResults exports scan results to bytes in the specified format
// Implements Requirements 6.2, 6.4
func (rm *DefaultResultManager) ExportResults(results *ScanResult, format OutputFormat) ([]byte, error) {
	if results == nil {
		return nil, fmt.Errorf("scan results cannot be nil")
	}

	switch format {
	case OutputFormatJSON:
		return rm.exportJSON(results)
	case OutputFormatXML:
		return rm.exportXML(results)
	case OutputFormatText:
		return rm.exportText(results)
	default:
		return nil, fmt.Errorf("unsupported output format: %s", format.String())
	}
}

// LoadResults loads scan results from a file
// Implements Requirements 6.5
func (rm *DefaultResultManager) LoadResults(filename string) (*ScanResult, error) {
	if filename == "" {
		return nil, fmt.Errorf("filename cannot be empty")
	}

	// Check if file exists
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return nil, fmt.Errorf("file does not exist: %s", filename)
	}

	// Read file content
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filename, err)
	}

	// Determine format from file extension
	ext := strings.ToLower(filepath.Ext(filename))
	var results ScanResult

	switch ext {
	case ".json":
		if err := json.Unmarshal(data, &results); err != nil {
			return nil, fmt.Errorf("failed to parse JSON file %s: %w", filename, err)
		}
	case ".xml":
		if err := xml.Unmarshal(data, &results); err != nil {
			return nil, fmt.Errorf("failed to parse XML file %s: %w", filename, err)
		}
	default:
		// Try JSON first, then XML
		if err := json.Unmarshal(data, &results); err != nil {
			if xmlErr := xml.Unmarshal(data, &results); xmlErr != nil {
				return nil, fmt.Errorf("failed to parse file %s as JSON or XML: JSON error: %v, XML error: %v", filename, err, xmlErr)
			}
		}
	}

	return &results, nil
}

// exportJSON exports results to JSON format
func (rm *DefaultResultManager) exportJSON(results *ScanResult) ([]byte, error) {
	// Use indented JSON for better readability
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal results to JSON: %w", err)
	}
	return data, nil
}

// exportXML exports results to XML format
func (rm *DefaultResultManager) exportXML(results *ScanResult) ([]byte, error) {
	// Add XML header
	header := []byte(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")

	// Marshal to XML with indentation
	data, err := xml.MarshalIndent(results, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal results to XML: %w", err)
	}

	// Combine header and data
	result := append(header, data...)
	return result, nil
}

// exportText exports results to human-readable text format
func (rm *DefaultResultManager) exportText(results *ScanResult) ([]byte, error) {
	var sb strings.Builder

	// Header information
	sb.WriteString("Network Scan Results\n")
	sb.WriteString("===================\n\n")

	// Scan information
	sb.WriteString(fmt.Sprintf("Scan Date: %s\n", results.Timestamp.Format("2006-01-02 15:04:05")))
	sb.WriteString(fmt.Sprintf("Scan Type: %s\n", results.ScanConfig.ScanType.String()))
	sb.WriteString(fmt.Sprintf("Targets: %s\n", strings.Join(results.ScanConfig.Targets, ", ")))

	if len(results.ScanConfig.Ports) > 0 {
		sb.WriteString(fmt.Sprintf("Ports: %v\n", results.ScanConfig.Ports))
	}

	sb.WriteString(fmt.Sprintf("Service Detection: %t\n", results.ScanConfig.ServiceDetect))
	sb.WriteString(fmt.Sprintf("OS Detection: %t\n", results.ScanConfig.OSDetect))
	sb.WriteString(fmt.Sprintf("Max Threads: %d\n", results.ScanConfig.MaxThreads))
	sb.WriteString(fmt.Sprintf("Timeout: %s\n", results.ScanConfig.Timeout.String()))
	sb.WriteString("\n")

	// Statistics
	sb.WriteString("Scan Statistics\n")
	sb.WriteString("---------------\n")
	sb.WriteString(fmt.Sprintf("Hosts Scanned: %d/%d\n", results.Statistics.HostsScanned, results.Statistics.HostsTotal))
	sb.WriteString(fmt.Sprintf("Ports Scanned: %d/%d\n", results.Statistics.PortsScanned, results.Statistics.PortsTotal))
	sb.WriteString(fmt.Sprintf("Open Ports: %d\n", results.Statistics.OpenPorts))
	sb.WriteString(fmt.Sprintf("Closed Ports: %d\n", results.Statistics.ClosedPorts))
	sb.WriteString(fmt.Sprintf("Filtered Ports: %d\n", results.Statistics.FilteredPorts))
	sb.WriteString(fmt.Sprintf("Elapsed Time: %s\n", results.Statistics.ElapsedTime.String()))
	sb.WriteString(fmt.Sprintf("Scan Rate: %.2f ports/sec\n", results.Statistics.ScanRate))
	sb.WriteString("\n")

	// Host results - organized by host with nested port/service data (Requirement 6.4)
	sb.WriteString("Host Results\n")
	sb.WriteString("============\n\n")

	for _, host := range results.Hosts {
		sb.WriteString(fmt.Sprintf("Host: %s (%s)\n", host.Target, host.Status.String()))
		sb.WriteString(fmt.Sprintf("Response Time: %s\n", host.ResponseTime.String()))

		// OS Information
		if host.OS.Family != "" {
			sb.WriteString(fmt.Sprintf("OS: %s %s (%.1f%% confidence)\n", host.OS.Family, host.OS.Version, host.OS.Confidence))
			if len(host.OS.Matches) > 1 {
				sb.WriteString("Other OS Matches:\n")
				for _, match := range host.OS.Matches[1:] { // Skip first match as it's already shown
					sb.WriteString(fmt.Sprintf("  - %s %s (%.1f%%)\n", match.Name, match.Version, match.Confidence))
				}
			}
		}

		// Port results
		if len(host.Ports) > 0 {
			sb.WriteString("\nPorts:\n")
			sb.WriteString("------\n")

			for _, port := range host.Ports {
				sb.WriteString(fmt.Sprintf("  %d/%s\t%s", port.Port, port.Protocol, port.State.String()))

				// Service information
				if port.Service.Name != "" {
					sb.WriteString(fmt.Sprintf("\t%s", port.Service.Name))
					if port.Service.Version != "" {
						sb.WriteString(fmt.Sprintf(" %s", port.Service.Version))
					}
					if port.Service.Product != "" {
						sb.WriteString(fmt.Sprintf(" (%s)", port.Service.Product))
					}
					if port.Service.Confidence > 0 {
						sb.WriteString(fmt.Sprintf(" [%.1f%%]", port.Service.Confidence))
					}
				}

				// Banner information
				if port.Banner != "" {
					sb.WriteString(fmt.Sprintf("\n    Banner: %s", strings.ReplaceAll(port.Banner, "\n", "\\n")))
				}

				// Extra service info
				if len(port.Service.ExtraInfo) > 0 {
					sb.WriteString("\n    Extra Info:")
					for _, kv := range port.Service.ExtraInfo {
						sb.WriteString(fmt.Sprintf(" %s=%s", kv.Key, kv.Value))
					}
				}

				sb.WriteString(fmt.Sprintf("\t(%.2fms)\n", float64(port.ResponseTime.Nanoseconds())/1000000.0))
			}
		} else {
			sb.WriteString("\nNo open ports found.\n")
		}

		sb.WriteString("\n")
	}

	return []byte(sb.String()), nil
}

// ExportWebServicesForScanning exports discovered web services to valid-url.txt for endpoint scanning
// Implements Requirements 9.2, 9.3
func (rm *DefaultResultManager) ExportWebServicesForScanning(results *ScanResult, outputPath string) error {
	if results == nil {
		return fmt.Errorf("scan results cannot be nil")
	}

	// Extract web services (HTTP/HTTPS services on common web ports)
	webServices := rm.extractWebServices(results)

	if len(webServices) == 0 {
		return fmt.Errorf("no web services found in scan results")
	}

	// Write to file in format expected by scanner module
	return rm.writeWebServicesToFile(webServices, outputPath)
}

// ExportTargetsForBruteForce exports discovered services to format suitable for brute force attacks
// Implements Requirements 9.2, 9.3
func (rm *DefaultResultManager) ExportTargetsForBruteForce(results *ScanResult, outputPath string) error {
	if results == nil {
		return fmt.Errorf("scan results cannot be nil")
	}

	// Extract services that commonly have authentication (SSH, FTP, HTTP, etc.)
	authServices := rm.extractAuthenticationServices(results)

	if len(authServices) == 0 {
		return fmt.Errorf("no authentication services found in scan results")
	}

	// Write to file in format expected by cracker module
	return rm.writeAuthServicesToFile(authServices, outputPath)
}

// ExportTargetsForDDoS exports discovered web services to format suitable for DDoS scanning
// Implements Requirements 9.2, 9.3
func (rm *DefaultResultManager) ExportTargetsForDDoS(results *ScanResult, outputPath string) error {
	if results == nil {
		return fmt.Errorf("scan results cannot be nil")
	}

	// Extract HTTP/HTTPS services suitable for DDoS testing
	ddosTargets := rm.extractDDoSTargets(results)

	if len(ddosTargets) == 0 {
		return fmt.Errorf("no suitable DDoS targets found in scan results")
	}

	// Write to file in cURL format expected by DDoS module
	return rm.writeDDoSTargetsToFile(ddosTargets, outputPath)
}

// extractWebServices extracts web services from scan results
func (rm *DefaultResultManager) extractWebServices(results *ScanResult) []string {
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

// extractAuthenticationServices extracts services that commonly have authentication
func (rm *DefaultResultManager) extractAuthenticationServices(results *ScanResult) []AuthService {
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

// extractDDoSTargets extracts HTTP/HTTPS services suitable for DDoS testing
func (rm *DefaultResultManager) extractDDoSTargets(results *ScanResult) []DDoSTarget {
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

// writeWebServicesToFile writes web services to file in format expected by scanner module
func (rm *DefaultResultManager) writeWebServicesToFile(webServices []string, outputPath string) error {
	// Use Letgo's data directory structure if relative path
	if !filepath.IsAbs(outputPath) {
		dataDir := paths.GetDataDir()
		outputPath = filepath.Join(dataDir, outputPath)
	}

	// Ensure the directory exists
	dir := filepath.Dir(outputPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", outputPath, err)
	}
	defer file.Close()

	// Write header comment
	header := "# Web services discovered by Network Mapper\n"
	header += fmt.Sprintf("# Generated: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	header += fmt.Sprintf("# Total services: %d\n\n", len(webServices))

	if _, err := file.WriteString(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write each web service URL
	for _, service := range webServices {
		if _, err := file.WriteString(service + "\n"); err != nil {
			return fmt.Errorf("failed to write service URL: %w", err)
		}
	}

	return nil
}

// writeAuthServicesToFile writes authentication services to file
func (rm *DefaultResultManager) writeAuthServicesToFile(authServices []AuthService, outputPath string) error {
	// Use Letgo's data directory structure if relative path
	if !filepath.IsAbs(outputPath) {
		dataDir := paths.GetDataDir()
		outputPath = filepath.Join(dataDir, outputPath)
	}

	// Ensure the directory exists
	dir := filepath.Dir(outputPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", outputPath, err)
	}
	defer file.Close()

	// Write header comment
	header := "# Authentication services discovered by Network Mapper\n"
	header += fmt.Sprintf("# Generated: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	header += fmt.Sprintf("# Total services: %d\n", len(authServices))
	header += "# Format: host:port|service|protocol|banner\n\n"

	if _, err := file.WriteString(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write each authentication service
	for _, service := range authServices {
		line := fmt.Sprintf("%s:%d|%s|%s|%s\n",
			service.Host, service.Port, service.Service, service.Protocol,
			strings.ReplaceAll(service.Banner, "\n", "\\n"))

		if _, err := file.WriteString(line); err != nil {
			return fmt.Errorf("failed to write service: %w", err)
		}
	}

	return nil
}

// writeDDoSTargetsToFile writes DDoS targets to file in cURL format
func (rm *DefaultResultManager) writeDDoSTargetsToFile(ddosTargets []DDoSTarget, outputPath string) error {
	// Use Letgo's data directory structure if relative path
	if !filepath.IsAbs(outputPath) {
		dataDir := paths.GetDataDir()
		outputPath = filepath.Join(dataDir, outputPath)
	}

	// Ensure the directory exists
	dir := filepath.Dir(outputPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", outputPath, err)
	}
	defer file.Close()

	// Write header comment
	header := "# DDoS targets discovered by Network Mapper\n"
	header += fmt.Sprintf("# Generated: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	header += fmt.Sprintf("# Total targets: %d\n", len(ddosTargets))
	header += "# Format: cURL commands for DDoS testing\n\n"

	if _, err := file.WriteString(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write each target as a cURL command
	for _, target := range ddosTargets {
		curlCmd := fmt.Sprintf("curl -X GET %s\n", target.URL)

		if _, err := file.WriteString(curlCmd); err != nil {
			return fmt.Errorf("failed to write cURL command: %w", err)
		}
	}

	return nil
}

// MergeResults merges multiple scan results into a single result
// This is useful for combining results from multiple scans
func (rm *DefaultResultManager) MergeResults(results ...*ScanResult) (*ScanResult, error) {
	if len(results) == 0 {
		return nil, fmt.Errorf("no results to merge")
	}

	if len(results) == 1 {
		return results[0], nil
	}

	// Use the first result as the base
	merged := &ScanResult{
		Timestamp:  results[0].Timestamp,
		ScanConfig: results[0].ScanConfig,
		Hosts:      make([]HostResult, 0),
		Statistics: ScanStatistics{},
	}

	// Merge hosts from all results
	hostMap := make(map[string]HostResult)

	for _, result := range results {
		for _, host := range result.Hosts {
			if existing, exists := hostMap[host.Target]; exists {
				// Merge port results for the same host
				portMap := make(map[int]PortResult)

				// Add existing ports
				for _, port := range existing.Ports {
					portMap[port.Port] = port
				}

				// Add new ports (overwrite if same port)
				for _, port := range host.Ports {
					portMap[port.Port] = port
				}

				// Convert back to slice
				ports := make([]PortResult, 0, len(portMap))
				for _, port := range portMap {
					ports = append(ports, port)
				}

				// Update host with merged ports
				host.Ports = ports
			}

			hostMap[host.Target] = host
		}

		// Merge statistics
		merged.Statistics.HostsScanned += result.Statistics.HostsScanned
		merged.Statistics.HostsTotal += result.Statistics.HostsTotal
		merged.Statistics.PortsScanned += result.Statistics.PortsScanned
		merged.Statistics.PortsTotal += result.Statistics.PortsTotal
		merged.Statistics.OpenPorts += result.Statistics.OpenPorts
		merged.Statistics.ClosedPorts += result.Statistics.ClosedPorts
		merged.Statistics.FilteredPorts += result.Statistics.FilteredPorts

		// Update timing information
		if result.Statistics.StartTime.Before(merged.Statistics.StartTime) || merged.Statistics.StartTime.IsZero() {
			merged.Statistics.StartTime = result.Statistics.StartTime
		}
		if result.Statistics.EndTime.After(merged.Statistics.EndTime) {
			merged.Statistics.EndTime = result.Statistics.EndTime
		}
	}

	// Convert host map back to slice
	for _, host := range hostMap {
		merged.Hosts = append(merged.Hosts, host)
	}

	// Calculate final statistics
	if !merged.Statistics.StartTime.IsZero() && !merged.Statistics.EndTime.IsZero() {
		merged.Statistics.ElapsedTime = merged.Statistics.EndTime.Sub(merged.Statistics.StartTime)
		if merged.Statistics.ElapsedTime > 0 {
			merged.Statistics.ScanRate = float64(merged.Statistics.PortsScanned) / merged.Statistics.ElapsedTime.Seconds()
		}
	}

	return merged, nil
}
