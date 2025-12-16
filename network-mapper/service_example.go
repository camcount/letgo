package networkmapper

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// ExampleServiceDetection demonstrates how to use the service detector
func ExampleServiceDetection() {
	// Create a service detector
	logger := log.New(os.Stdout, "service-detector: ", log.LstdFlags)
	detector := NewDefaultServiceDetector(2*time.Second, 2, logger)

	// Example targets and ports to test
	targets := []string{"127.0.0.1", "google.com"}
	ports := []int{80, 443, 22, 21}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Println("Service Detection Example")
	fmt.Println("========================")

	for _, target := range targets {
		fmt.Printf("\nScanning target: %s\n", target)
		fmt.Println("-------------------")

		for _, port := range ports {
			fmt.Printf("Port %d: ", port)

			serviceInfo := detector.DetectService(ctx, target, port)

			if serviceInfo.Name != "" {
				fmt.Printf("%s", serviceInfo.Name)
				if serviceInfo.Version != "" {
					fmt.Printf(" (version: %s)", serviceInfo.Version)
				}
				fmt.Printf(" [confidence: %.1f%%]", serviceInfo.Confidence)

				if serviceInfo.Banner != "" {
					fmt.Printf("\n  Banner: %s", serviceInfo.Banner)
				}

				if len(serviceInfo.ExtraInfo) > 0 {
					fmt.Printf("\n  Extra info:")
					for _, kv := range serviceInfo.ExtraInfo {
						fmt.Printf("\n    %s: %s", kv.Key, kv.Value)
					}
				}
			} else {
				fmt.Printf("unknown service")
			}
			fmt.Println()
		}
	}
}

// ExamplePortScannerWithServiceDetection shows how to integrate service detection with port scanning
func ExamplePortScannerWithServiceDetection() {
	// Create scanner and detector
	logger := log.New(os.Stdout, "scanner: ", log.LstdFlags)
	scanner := NewDefaultPortScanner(1*time.Second, 1, logger)
	detector := NewDefaultServiceDetector(2*time.Second, 1, logger)

	target := "127.0.0.1"
	ports := []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Println("Port Scanning with Service Detection Example")
	fmt.Println("===========================================")
	fmt.Printf("Scanning target: %s\n\n", target)

	// Scan ports
	results := scanner.ScanPorts(ctx, target, ports, ScanTypeTCPConnect)

	fmt.Printf("%-6s %-10s %-15s %-20s %s\n", "Port", "State", "Service", "Version", "Banner")
	fmt.Println(strings.Repeat("-", 80))

	for _, result := range results {
		fmt.Printf("%-6d %-10s", result.Port, result.State.String())

		if result.State == PortOpen {
			// Perform service detection on open ports
			serviceInfo := detector.DetectService(ctx, target, result.Port)

			serviceName := serviceInfo.Name
			if serviceName == "" {
				serviceName = "unknown"
			}

			version := serviceInfo.Version
			if version == "" {
				version = "-"
			}

			banner := serviceInfo.Banner
			if len(banner) > 30 {
				banner = banner[:27] + "..."
			}
			if banner == "" {
				banner = "-"
			}

			fmt.Printf(" %-15s %-20s %s", serviceName, version, banner)
		} else {
			fmt.Printf(" %-15s %-20s %s", "-", "-", "-")
		}
		fmt.Println()
	}
}
