package consolemenu

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	networkmapper "github.com/letgo/network-mapper"
	"github.com/letgo/paths"
)

// networkMapper provides the network mapping functionality in the console menu
func (m *Menu) networkMapper() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("                    NETWORK MAPPER (NMAP-like)")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("\nNetwork discovery and port scanning with service detection")
	fmt.Println()

	// Get target(s)
	fmt.Print("Enter target(s) (IP, hostname, or CIDR range, comma-separated): ")
	targetsInput, _ := reader.ReadString('\n')
	targetsInput = strings.TrimSpace(targetsInput)

	if targetsInput == "" {
		fmt.Println("Error: Target is required.")
		return
	}

	// Parse targets
	targets := strings.Split(targetsInput, ",")
	for i := range targets {
		targets[i] = strings.TrimSpace(targets[i])
	}

	// Get scan profile
	fmt.Println("\nSelect scan profile:")
	fmt.Println("  [1] Quick scan (top 100 ports)")
	fmt.Println("  [2] Comprehensive scan (top 1000 ports + service detection)")
	fmt.Println("  [3] Stealth scan (slow timing, evasion techniques)")
	fmt.Println("  [4] Vulnerability scan (common vulnerability ports)")
	fmt.Println("  [5] Custom scan (specify parameters)")
	fmt.Print("Enter choice (1-5, default: 2): ")
	profileChoice, _ := reader.ReadString('\n')
	profileChoice = strings.TrimSpace(profileChoice)

	var config networkmapper.ScanConfig
	config.Targets = targets
	config.MaxThreads = 50
	config.Timeout = 5 * time.Second
	config.OutputFormat = networkmapper.OutputFormatText

	switch profileChoice {
	case "1":
		// Quick scan
		config.Ports = getTopPorts(100)
		config.ServiceDetect = false
		config.OSDetect = false
		fmt.Println("✓ Quick scan profile selected")
	case "3":
		// Stealth scan
		config.Ports = getTopPorts(200)
		config.ServiceDetect = true
		config.OSDetect = false
		config.MaxThreads = 10
		config.Timeout = 10 * time.Second
		fmt.Println("✓ Stealth scan profile selected")
	case "4":
		// Vulnerability scan
		config.Ports = getVulnerabilityPorts()
		config.ServiceDetect = true
		config.OSDetect = true
		config.MaxThreads = 25
		fmt.Println("✓ Vulnerability scan profile selected")
	case "5":
		// Custom scan
		m.configureCustomScan(&config, reader)
	default:
		// Comprehensive scan (default)
		config.Ports = getTopPorts(1000)
		config.ServiceDetect = true
		config.OSDetect = true
		fmt.Println("✓ Comprehensive scan profile selected")
	}

	// Ask for output file
	configManager := networkmapper.NewConfigManager()
	defaultOutput := configManager.GetDefaultResultPath(config.OutputFormat)
	fmt.Printf("Enter output file path (default: %s): ", defaultOutput)
	outputPath, _ := reader.ReadString('\n')
	outputPath = strings.TrimSpace(outputPath)
	if outputPath == "" {
		outputPath = defaultOutput
	}
	config.OutputFile = outputPath

	// Set up progress callback
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("Starting network scan...")
	fmt.Println("Press Ctrl+C to stop the scan")
	fmt.Println(strings.Repeat("=", 70))

	config.OnProgress = func(progress networkmapper.ProgressInfo) {
		percentage := 0.0
		if progress.PortsTotal > 0 {
			percentage = float64(progress.PortsScanned) / float64(progress.PortsTotal) * 100
		}
		
		fmt.Printf("\r[%s] Progress: %.1f%% | Hosts: %d/%d | Ports: %d/%d | Rate: %.1f p/s | ETA: %s",
			progress.CurrentTarget,
			percentage,
			progress.HostsScanned,
			progress.HostsTotal,
			progress.PortsScanned,
			progress.PortsTotal,
			progress.ScanRate,
			formatDuration(progress.EstimatedTime))
	}

	// Create scanner engine and perform scan
	engine := networkmapper.NewScannerEngine()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	results, err := engine.Scan(ctx, config)
	fmt.Print("\r" + strings.Repeat(" ", 100) + "\r") // Clear progress line

	if err != nil {
		fmt.Printf("Error during scan: %v\n", err)
		return
	}

	// Display results summary
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("                    SCAN RESULTS")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("Scan completed in: %s\n", results.Statistics.ElapsedTime)
	fmt.Printf("Hosts scanned: %d\n", results.Statistics.HostsScanned)
	fmt.Printf("Total ports scanned: %d\n", results.Statistics.PortsScanned)
	fmt.Printf("Open ports found: %d\n", results.Statistics.OpenPorts)
	fmt.Printf("Closed ports: %d\n", results.Statistics.ClosedPorts)
	fmt.Printf("Filtered ports: %d\n", results.Statistics.FilteredPorts)
	fmt.Printf("Average scan rate: %.2f ports/sec\n", results.Statistics.ScanRate)

	// Display host results
	upHosts := 0
	for _, host := range results.Hosts {
		if host.Status == networkmapper.HostUp {
			upHosts++
		}
	}
	fmt.Printf("Hosts up: %d\n", upHosts)

	if upHosts > 0 {
		fmt.Println("\n" + strings.Repeat("-", 70))
		fmt.Println("HOST DETAILS")
		fmt.Println(strings.Repeat("-", 70))

		for _, host := range results.Hosts {
			if host.Status != networkmapper.HostUp {
				continue
			}

			fmt.Printf("\nHost: %s (%s)\n", host.Target, host.Status.String())
			if host.OS.Family != "" {
				fmt.Printf("OS: %s %s (%.1f%% confidence)\n", host.OS.Family, host.OS.Version, host.OS.Confidence)
			}

			openPorts := 0
			for _, port := range host.Ports {
				if port.State == networkmapper.PortOpen {
					openPorts++
				}
			}

			if openPorts > 0 {
				fmt.Printf("Open ports (%d):\n", openPorts)
				for _, port := range host.Ports {
					if port.State == networkmapper.PortOpen {
						fmt.Printf("  %d/%s\t%s", port.Port, port.Protocol, port.State.String())
						if port.Service.Name != "" {
							fmt.Printf("\t%s", port.Service.Name)
							if port.Service.Version != "" {
								fmt.Printf(" %s", port.Service.Version)
							}
						}
						fmt.Println()
					}
				}
			} else {
				fmt.Println("No open ports found")
			}
		}
	}

	// Save results
	resultManager := networkmapper.NewResultManager()
	if err := resultManager.SaveResults(results, config.OutputFormat, config.OutputFile); err != nil {
		fmt.Printf("Warning: Failed to save results: %v\n", err)
	} else {
		fmt.Printf("\n✓ Results saved to: %s\n", config.OutputFile)
	}

	// Ask about integration with other modules
	m.offerIntegrationOptions(results, resultManager, reader)

	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("Network scan complete! Returning to main menu...")
	fmt.Println()
}
// configureCustomScan allows user to configure custom scan parameters
func (m *Menu) configureCustomScan(config *networkmapper.ScanConfig, reader *bufio.Reader) {
	fmt.Println("\n===== Custom Scan Configuration =====")

	// Port specification
	fmt.Print("Enter ports to scan (comma-separated, ranges with -, or 'top1000'): ")
	portsInput, _ := reader.ReadString('\n')
	portsInput = strings.TrimSpace(portsInput)

	if portsInput == "" || portsInput == "top1000" {
		config.Ports = getTopPorts(1000)
	} else {
		ports, err := parsePorts(portsInput)
		if err != nil {
			fmt.Printf("Error parsing ports: %v, using top 1000\n", err)
			config.Ports = getTopPorts(1000)
		} else {
			config.Ports = ports
		}
	}

	// Service detection
	fmt.Print("Enable service detection? (y/n, default: y): ")
	serviceDetect, _ := reader.ReadString('\n')
	serviceDetect = strings.TrimSpace(strings.ToLower(serviceDetect))
	config.ServiceDetect = serviceDetect != "n" && serviceDetect != "no"

	// OS detection
	fmt.Print("Enable OS detection? (y/n, default: y): ")
	osDetect, _ := reader.ReadString('\n')
	osDetect = strings.TrimSpace(strings.ToLower(osDetect))
	config.OSDetect = osDetect != "n" && osDetect != "no"

	// Thread count
	fmt.Print("Number of threads (default: 50): ")
	threadsStr, _ := reader.ReadString('\n')
	threadsStr = strings.TrimSpace(threadsStr)
	if threadsStr != "" {
		if threads, err := strconv.Atoi(threadsStr); err == nil && threads > 0 {
			config.MaxThreads = threads
		}
	}

	// Timeout
	fmt.Print("Timeout per port in seconds (default: 5): ")
	timeoutStr, _ := reader.ReadString('\n')
	timeoutStr = strings.TrimSpace(timeoutStr)
	if timeoutStr != "" {
		if timeout, err := strconv.Atoi(timeoutStr); err == nil && timeout > 0 {
			config.Timeout = time.Duration(timeout) * time.Second
		}
	}

	fmt.Println("✓ Custom scan configuration complete")
}

// offerIntegrationOptions offers integration with other Letgo modules
func (m *Menu) offerIntegrationOptions(results *networkmapper.ScanResult, resultManager networkmapper.ResultManager, reader *bufio.Reader) {
	// Check if we have any web services or authentication services
	hasWebServices := m.hasWebServices(results)
	hasAuthServices := m.hasAuthServices(results)

	if !hasWebServices && !hasAuthServices {
		fmt.Println("\nNo services suitable for additional testing found.")
		return
	}

	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("                    INTEGRATION OPTIONS")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("Export discovered services for use with other Letgo modules:")

	options := []string{}
	if hasWebServices {
		fmt.Println("  [1] Export web services for endpoint scanning")
		fmt.Println("  [2] Export web services for DDoS testing")
		options = append(options, "web-scan", "web-ddos")
	}
	if hasAuthServices {
		fmt.Println("  [3] Export authentication services for brute force attacks")
		options = append(options, "auth-brute")
	}
	fmt.Println("  [0] Skip integration")

	fmt.Print("\nSelect integration option(s) (comma-separated, or 0 to skip): ")
	choiceInput, _ := reader.ReadString('\n')
	choiceInput = strings.TrimSpace(choiceInput)

	if choiceInput == "0" || choiceInput == "" {
		return
	}

	choices := strings.Split(choiceInput, ",")
	dataDir := paths.GetDataDir()

	for _, choice := range choices {
		choice = strings.TrimSpace(choice)
		switch choice {
		case "1":
			if hasWebServices {
				outputPath := filepath.Join(dataDir, "valid-url.txt")
				if err := resultManager.ExportWebServicesForScanning(results, outputPath); err != nil {
					fmt.Printf("Error exporting web services: %v\n", err)
				} else {
					fmt.Printf("✓ Web services exported to: %s\n", outputPath)
					fmt.Println("  Use 'Scan for Login Endpoints' to test these services")
				}
			}
		case "2":
			if hasWebServices {
				outputPath := filepath.Join(dataDir, "ddos-targets", "network-mapper-targets.txt")
				if err := resultManager.ExportTargetsForDDoS(results, outputPath); err != nil {
					fmt.Printf("Error exporting DDoS targets: %v\n", err)
				} else {
					fmt.Printf("✓ DDoS targets exported to: %s\n", outputPath)
					fmt.Println("  Use 'DDoS Attack (cURL)' to test these targets")
				}
			}
		case "3":
			if hasAuthServices {
				outputPath := filepath.Join(dataDir, "auth-services.txt")
				if err := resultManager.ExportTargetsForBruteForce(results, outputPath); err != nil {
					fmt.Printf("Error exporting authentication services: %v\n", err)
				} else {
					fmt.Printf("✓ Authentication services exported to: %s\n", outputPath)
					fmt.Println("  Use 'Attack Brute force with cURL' to test these services")
				}
			}
		}
	}
}

// hasWebServices checks if scan results contain web services
func (m *Menu) hasWebServices(results *networkmapper.ScanResult) bool {
	webPorts := map[int]bool{80: true, 443: true, 8080: true, 8443: true, 8000: true, 8888: true, 3000: true, 5000: true}
	
	for _, host := range results.Hosts {
		if host.Status != networkmapper.HostUp {
			continue
		}
		
		for _, port := range host.Ports {
			if port.State != networkmapper.PortOpen {
				continue
			}
			
			if webPorts[port.Port] || strings.Contains(strings.ToLower(port.Service.Name), "http") {
				return true
			}
		}
	}
	
	return false
}

// hasAuthServices checks if scan results contain authentication services
func (m *Menu) hasAuthServices(results *networkmapper.ScanResult) bool {
	authPorts := map[int]bool{
		21: true, 22: true, 23: true, 25: true, 80: true, 110: true, 
		143: true, 443: true, 993: true, 995: true, 3389: true,
		5432: true, 3306: true, 1433: true, 1521: true,
	}
	
	for _, host := range results.Hosts {
		if host.Status != networkmapper.HostUp {
			continue
		}
		
		for _, port := range host.Ports {
			if port.State != networkmapper.PortOpen {
				continue
			}
			
			if authPorts[port.Port] {
				return true
			}
		}
	}
	
	return false
}

// getTopPorts returns the top N most common ports
func getTopPorts(n int) []int {
	// Top 1000 most common ports (truncated for brevity, showing top 100)
	topPorts := []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
		1723, 3306, 3389, 5432, 5900, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007,
		7000, 7001, 7002, 7003, 7004, 7005, 7006, 7007, 7008, 7009, 8000, 8008, 8080, 8443, 8888,
		9000, 9001, 9002, 9003, 9004, 9005, 9006, 9007, 9008, 9009, 9010, 9011, 9012, 9013, 9014, 9015,
		10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165, 49167, 49175, 49176,
		1025, 1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040, 1041, 1042, 1043, 1044,
		1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060,
	}
	
	if n > len(topPorts) {
		// If requesting more than available, return all and fill with sequential ports
		result := make([]int, n)
		copy(result, topPorts)
		for i := len(topPorts); i < n; i++ {
			result[i] = i + 1
		}
		return result
	}
	
	return topPorts[:n]
}

// getVulnerabilityPorts returns ports commonly associated with vulnerabilities
func getVulnerabilityPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
		1433, 1521, 3306, 3389, 5432, 5900, 6379, 11211, 27017, 50070,
		// Web application ports
		8000, 8008, 8080, 8443, 8888, 9000, 9200, 9300,
		// Database ports
		1521, 1433, 3306, 5432, 6379, 27017, 50070,
		// Remote access ports
		3389, 5900, 5901, 5902, 5903, 5904, 5905,
		// Common service ports
		161, 162, 389, 636, 1024, 1025, 2049, 2121, 2375, 2376,
	}
}

// parsePorts parses port specification string into slice of port numbers
func parsePorts(portsStr string) ([]int, error) {
	var ports []int
	parts := strings.Split(portsStr, ",")
	
	for _, part := range parts {
		part = strings.TrimSpace(part)
		
		if strings.Contains(part, "-") {
			// Handle range (e.g., "80-90")
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			
			start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid start port: %s", rangeParts[0])
			}
			
			end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid end port: %s", rangeParts[1])
			}
			
			if start > end || start < 1 || end > 65535 {
				return nil, fmt.Errorf("invalid port range: %d-%d", start, end)
			}
			
			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
		} else {
			// Handle single port
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			
			if port < 1 || port > 65535 {
				return nil, fmt.Errorf("port out of range: %d", port)
			}
			
			ports = append(ports, port)
		}
	}
	
	return ports, nil
}

// formatDuration formats a duration in a human-readable way
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	} else if d < time.Hour {
		return fmt.Sprintf("%.1fm", d.Minutes())
	} else {
		return fmt.Sprintf("%.1fh", d.Hours())
	}
}