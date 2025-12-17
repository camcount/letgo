package networkmapper

import (
	"context"
	"fmt"
	"log"
)

// ExampleIPResolver demonstrates the IP resolver functionality
func ExampleIPResolver() {
	resolver := NewIPResolver()
	ctx := context.Background()

	// Example 1: Resolve a hostname to IP addresses
	fmt.Println("=== Hostname Resolution Example ===")
	hostname := "google.com"
	resolvedIPs, err := resolver.ResolveHostname(ctx, hostname)
	if err != nil {
		log.Printf("Error resolving %s: %v", hostname, err)
	} else {
		fmt.Printf("Resolved %s to %d IP addresses:\n", hostname, len(resolvedIPs))
		for _, ip := range resolvedIPs {
			fmt.Printf("  - %s (%s) resolved at %s\n", ip.IP, ip.Type, ip.ResolvedAt.Format("15:04:05"))
		}
	}

	// Example 2: Reverse DNS lookup
	fmt.Println("\n=== Reverse DNS Lookup Example ===")
	testIP := "8.8.8.8"
	hostnames, err := resolver.ReverseLookup(ctx, testIP)
	if err != nil {
		log.Printf("Error performing reverse lookup for %s: %v", testIP, err)
	} else {
		fmt.Printf("Reverse lookup for %s found %d hostnames:\n", testIP, len(hostnames))
		for _, hostname := range hostnames {
			fmt.Printf("  - %s\n", hostname)
		}
	}

	// Example 3: Get IP information (ASN, geolocation)
	fmt.Println("\n=== IP Information Example ===")
	ipInfo, err := resolver.GetIPInfo(ctx, testIP)
	if err != nil {
		log.Printf("Error getting IP info for %s: %v", testIP, err)
	} else {
		fmt.Printf("IP Information for %s:\n", testIP)
		fmt.Printf("  ASN: %s\n", ipInfo.ASN)
		fmt.Printf("  Organization: %s\n", ipInfo.Organization)
		fmt.Printf("  ISP: %s\n", ipInfo.ISP)
		fmt.Printf("  Country: %s\n", ipInfo.Country)
		fmt.Printf("  Region: %s\n", ipInfo.Region)
		fmt.Printf("  City: %s\n", ipInfo.City)
		fmt.Printf("  Hosting Provider: %s\n", ipInfo.HostingProvider)
		fmt.Printf("  Cloud Platform: %s\n", ipInfo.CloudPlatform)
	}

	// Example 4: Resolve with specific options (IPv4 only)
	fmt.Println("\n=== IPv4-Only Resolution Example ===")
	options := ResolveOptions{
		IncludeIPv4: true,
		IncludeIPv6: false,
		Timeout:     resolver.timeout,
		Retries:     1,
	}
	ipv4Only, err := resolver.ResolveHostnameWithOptions(ctx, hostname, options)
	if err != nil {
		log.Printf("Error resolving %s (IPv4 only): %v", hostname, err)
	} else {
		fmt.Printf("IPv4-only resolution for %s found %d addresses:\n", hostname, len(ipv4Only))
		for _, ip := range ipv4Only {
			fmt.Printf("  - %s (%s)\n", ip.IP, ip.Type)
		}
	}
}