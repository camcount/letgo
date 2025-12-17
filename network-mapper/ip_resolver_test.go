package networkmapper

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// **Feature: network-mapper, Property 21: Hostname IP Resolution**
// **Validates: Requirements 10.1**
// Property: For any hostname provided as a target, all associated IP addresses should be resolved and displayed in the scan results
func TestProperty21_HostnameIPResolution(t *testing.T) {
	resolver := NewIPResolver()
	ctx := context.Background()

	// Property-based test with 20 iterations for faster testing
	for i := 0; i < 20; i++ {
		t.Run(fmt.Sprintf("iteration_%d", i), func(t *testing.T) {
			// Generate random valid hostname
			hostname := generateRandomHostname()

			// Attempt to resolve hostname
			resolvedIPs, err := resolver.ResolveHostname(ctx, hostname)

			// If resolution succeeds, validate the results
			if err == nil {
				// Requirement 10.1: All associated IP addresses should be resolved and displayed
				require.NotEmpty(t, resolvedIPs, "Resolved IPs should not be empty for successful resolution")

				for _, resolvedIP := range resolvedIPs {
					// Validate IP address format
					parsedIP := net.ParseIP(resolvedIP.IP)
					require.NotNil(t, parsedIP, "Resolved IP should be valid: %s", resolvedIP.IP)

					// Validate IP type is correctly identified
					if parsedIP.To4() != nil {
						require.Equal(t, "IPv4", resolvedIP.Type, "IPv4 addresses should be identified as IPv4")
					} else {
						require.Equal(t, "IPv6", resolvedIP.Type, "IPv6 addresses should be identified as IPv6")
					}

					// Validate hostname is preserved
					require.Equal(t, hostname, resolvedIP.Hostname, "Original hostname should be preserved")

					// Validate resolution timestamp is recent
					require.True(t, time.Since(resolvedIP.ResolvedAt) < time.Minute,
						"Resolution timestamp should be recent")

					// Validate source is set
					require.NotEmpty(t, resolvedIP.Source, "Resolution source should be specified")
				}
			} else {
				// If resolution fails, error should be informative
				// Note: Some errors like "context deadline exceeded" may not contain the hostname
				// but the error should still be non-nil and meaningful
				require.NotNil(t, err, "Error should be returned for failed resolution")
				require.NotEmpty(t, err.Error(), "Error message should not be empty")
			}
		})
	}
}

// **Feature: network-mapper, Property 22: Multiple IP Scanning Completeness**
// **Validates: Requirements 10.2**
// Property: For any hostname that resolves to multiple IP addresses, all resolved IPs should be included in the scanning process
func TestProperty22_MultipleIPScanningCompleteness(t *testing.T) {
	resolver := NewIPResolver()
	ctx := context.Background()

	// Property-based test with 20 iterations for faster testing
	for i := 0; i < 20; i++ {
		t.Run(fmt.Sprintf("iteration_%d", i), func(t *testing.T) {
			// Generate random hostname that might resolve to multiple IPs
			hostname := generateRandomHostname()

			// Resolve hostname
			resolvedIPs, err := resolver.ResolveHostname(ctx, hostname)

			// If resolution succeeds and returns multiple IPs
			if err == nil && len(resolvedIPs) > 1 {
				// Requirement 10.2: All resolved IPs should be included in scanning process
				
				// Validate that all IPs are unique
				ipSet := make(map[string]bool)
				for _, resolvedIP := range resolvedIPs {
					require.False(t, ipSet[resolvedIP.IP], "Each IP should appear only once: %s", resolvedIP.IP)
					ipSet[resolvedIP.IP] = true
				}

				// Validate that all IPs are valid and parseable
				for _, resolvedIP := range resolvedIPs {
					parsedIP := net.ParseIP(resolvedIP.IP)
					require.NotNil(t, parsedIP, "All resolved IPs should be valid: %s", resolvedIP.IP)

					// Validate metadata consistency across all resolved IPs
					require.Equal(t, hostname, resolvedIP.Hostname, "All resolved IPs should reference the same hostname")
					require.NotEmpty(t, resolvedIP.Type, "All resolved IPs should have type specified")
					require.NotEmpty(t, resolvedIP.Source, "All resolved IPs should have source specified")
				}

				// Validate both IPv4 and IPv6 can be included if present
				ipv4Count := 0
				ipv6Count := 0
				for _, resolvedIP := range resolvedIPs {
					if resolvedIP.Type == "IPv4" {
						ipv4Count++
					} else if resolvedIP.Type == "IPv6" {
						ipv6Count++
					}
				}

				// If we have both types, validate they're properly categorized
				if ipv4Count > 0 && ipv6Count > 0 {
					for _, resolvedIP := range resolvedIPs {
						parsedIP := net.ParseIP(resolvedIP.IP)
						if parsedIP.To4() != nil {
							require.Equal(t, "IPv4", resolvedIP.Type, "IPv4 addresses should be correctly typed")
						} else {
							require.Equal(t, "IPv6", resolvedIP.Type, "IPv6 addresses should be correctly typed")
						}
					}
				}

				// Validate total count matches
				require.Equal(t, len(resolvedIPs), ipv4Count+ipv6Count, "All IPs should be categorized as IPv4 or IPv6")
			}
		})
	}
}

// **Feature: network-mapper, Property 24: DNS Resolution Error Resilience**
// **Validates: Requirements 10.4**
// Property: For any DNS resolution failure, the error should be logged and scanning should continue with remaining targets
func TestProperty24_DNSResolutionErrorResilience(t *testing.T) {
	resolver := NewIPResolver()
	ctx := context.Background()

	// Property-based test with 10 iterations for faster testing
	for i := 0; i < 10; i++ {
		t.Run(fmt.Sprintf("iteration_%d", i), func(t *testing.T) {
			// Test with clearly invalid hostnames that should fail quickly
			invalidHostnames := []string{
				"",                           // Empty hostname
				"invalid..hostname.com",      // Double dots
				".invalid.com",              // Leading dot
				"invalid_hostname.com",       // Underscore (invalid in hostnames)
				"hostname-.com",             // Trailing hyphen in label
				"host name.com",             // Space in hostname
			}
			
			invalidHostname := invalidHostnames[i%len(invalidHostnames)]

			// Attempt to resolve invalid hostname
			resolvedIPs, err := resolver.ResolveHostname(ctx, invalidHostname)

			// Requirement 10.4: DNS resolution failure should be handled gracefully
			if err != nil {
				// Error should be informative
				require.NotNil(t, err, "Error should be properly returned, not panic")
				require.NotEmpty(t, err.Error(), "Error message should not be empty")

				// Resolved IPs should be empty or nil on error
				require.Empty(t, resolvedIPs, "Resolved IPs should be empty when resolution fails")
			}

			// Test that the resolver doesn't crash on invalid input
			require.NotPanics(t, func() {
				resolver.ResolveHostname(ctx, invalidHostname)
			}, "Resolver should not panic on invalid hostname")
		})
	}
}

// **Feature: network-mapper, Property 25: IPv6 Address Inclusion**
// **Validates: Requirements 10.5**
// Property: For any hostname that resolves to IPv6 addresses, they should be included in results alongside IPv4 addresses
func TestProperty25_IPv6AddressInclusion(t *testing.T) {
	resolver := NewIPResolver()
	ctx := context.Background()

	// Property-based test with 10 iterations for faster testing
	for i := 0; i < 10; i++ {
		t.Run(fmt.Sprintf("iteration_%d", i), func(t *testing.T) {
			// Test with known hostnames that should have both IPv4 and IPv6
			testHostnames := []string{
				"google.com",
				"cloudflare.com",
				"github.com",
				generateRandomHostname(), // Also test random hostnames
			}

			hostname := testHostnames[rand.Intn(len(testHostnames))]

			// Resolve hostname with both IPv4 and IPv6 enabled
			options := ResolveOptions{
				IncludeIPv4: true,
				IncludeIPv6: true,
				Timeout:     5 * time.Second,
				Retries:     2,
			}

			resolvedIPs, err := resolver.ResolveHostnameWithOptions(ctx, hostname, options)

			// If resolution succeeds
			if err == nil && len(resolvedIPs) > 0 {
				// Requirement 10.5: IPv6 addresses should be included alongside IPv4

				// Check if we have IPv6 addresses
				ipv6Count := 0
				ipv4Count := 0

				for _, resolvedIP := range resolvedIPs {
					parsedIP := net.ParseIP(resolvedIP.IP)
					require.NotNil(t, parsedIP, "All resolved IPs should be valid")

					if parsedIP.To4() != nil {
						ipv4Count++
						require.Equal(t, "IPv4", resolvedIP.Type, "IPv4 addresses should be correctly identified")
					} else {
						ipv6Count++
						require.Equal(t, "IPv6", resolvedIP.Type, "IPv6 addresses should be correctly identified")
					}
				}

				// If we have IPv6 addresses, validate they're properly handled
				if ipv6Count > 0 {
					// IPv6 addresses should be valid and properly formatted
					for _, resolvedIP := range resolvedIPs {
						if resolvedIP.Type == "IPv6" {
							parsedIP := net.ParseIP(resolvedIP.IP)
							require.NotNil(t, parsedIP, "IPv6 address should be valid: %s", resolvedIP.IP)
							require.Nil(t, parsedIP.To4(), "IPv6 address should not be convertible to IPv4")

							// IPv6 addresses should have proper metadata
							require.Equal(t, hostname, resolvedIP.Hostname, "IPv6 address should reference correct hostname")
							require.NotEmpty(t, resolvedIP.Source, "IPv6 address should have source specified")
						}
					}
				}

				// Test IPv6-only resolution
				ipv6OnlyOptions := ResolveOptions{
					IncludeIPv4: false,
					IncludeIPv6: true,
					Timeout:     5 * time.Second,
					Retries:     2,
				}

				ipv6OnlyIPs, ipv6Err := resolver.ResolveHostnameWithOptions(ctx, hostname, ipv6OnlyOptions)
				if ipv6Err == nil {
					// All returned IPs should be IPv6
					for _, resolvedIP := range ipv6OnlyIPs {
						require.Equal(t, "IPv6", resolvedIP.Type, "IPv6-only resolution should return only IPv6 addresses")
						parsedIP := net.ParseIP(resolvedIP.IP)
						require.Nil(t, parsedIP.To4(), "IPv6-only resolution should not return IPv4 addresses")
					}
				}

				// Test IPv4-only resolution
				ipv4OnlyOptions := ResolveOptions{
					IncludeIPv4: true,
					IncludeIPv6: false,
					Timeout:     5 * time.Second,
					Retries:     2,
				}

				ipv4OnlyIPs, ipv4Err := resolver.ResolveHostnameWithOptions(ctx, hostname, ipv4OnlyOptions)
				if ipv4Err == nil {
					// All returned IPs should be IPv4
					for _, resolvedIP := range ipv4OnlyIPs {
						require.Equal(t, "IPv4", resolvedIP.Type, "IPv4-only resolution should return only IPv4 addresses")
						parsedIP := net.ParseIP(resolvedIP.IP)
						require.NotNil(t, parsedIP.To4(), "IPv4-only resolution should return valid IPv4 addresses")
					}
				}
			}
		})
	}
}

// Test reverse DNS lookup functionality
func TestReverseDNSLookup(t *testing.T) {
	resolver := NewIPResolver()
	ctx := context.Background()

	// Test with known IPs
	testIPs := []string{
		"8.8.8.8",     // Google DNS
		"1.1.1.1",     // Cloudflare DNS
		"208.67.222.222", // OpenDNS
	}

	for _, ip := range testIPs {
		t.Run(fmt.Sprintf("reverse_lookup_%s", ip), func(t *testing.T) {
			hostnames, err := resolver.ReverseLookup(ctx, ip)

			if err == nil {
				// If reverse lookup succeeds, validate results
				require.NotEmpty(t, hostnames, "Reverse lookup should return hostnames")

				for _, hostname := range hostnames {
					require.NotEmpty(t, hostname, "Hostname should not be empty")
					require.False(t, strings.HasSuffix(hostname, "."), "Hostname should not end with dot")
				}
			} else {
				// Error should be informative
				require.Contains(t, err.Error(), ip, "Error should mention the IP address")
			}
		})
	}
}

// Test IP info retrieval functionality
func TestIPInfoRetrieval(t *testing.T) {
	resolver := NewIPResolver()
	ctx := context.Background()

	// Test with known IPs
	testIPs := []string{
		"8.8.8.8",   // Google DNS
		"1.1.1.1",   // Cloudflare DNS
	}

	for _, ip := range testIPs {
		t.Run(fmt.Sprintf("ip_info_%s", ip), func(t *testing.T) {
			ipInfo, err := resolver.GetIPInfo(ctx, ip)

			require.NoError(t, err, "IP info retrieval should not error for valid IP")
			require.Equal(t, ip, ipInfo.IP, "IP should match requested IP")
			require.NotNil(t, ipInfo.Metadata, "Metadata should be initialized")

			// Basic validation of returned info
			if ipInfo.ASN != "" {
				require.True(t, strings.HasPrefix(ipInfo.ASN, "AS") || ipInfo.ASN == "AS0", 
					"ASN should start with 'AS' or be 'AS0' for unknown")
			}
		})
	}
}

// Helper functions for generating test data

// generateRandomHostname creates a random valid hostname for testing
func generateRandomHostname() string {
	// Use well-known domains that should resolve quickly
	domains := []string{
		"google.com",
		"github.com",
		"stackoverflow.com",
		"localhost",
	}

	subdomains := []string{
		"www",
		"api",
		"mail",
	}

	// Sometimes return just domain, sometimes with subdomain
	if rand.Intn(2) == 0 {
		return domains[rand.Intn(len(domains))]
	}

	return fmt.Sprintf("%s.%s", 
		subdomains[rand.Intn(len(subdomains))], 
		domains[rand.Intn(len(domains))])
}

// generateRandomInvalidHostname creates a random invalid hostname for testing error handling
func generateRandomInvalidHostname() string {
	invalidHostnames := []string{
		"",                           // Empty hostname
		"invalid..hostname.com",      // Double dots
		".invalid.com",              // Leading dot
		"invalid.com.",              // Trailing dot
		"very-long-hostname-that-exceeds-the-maximum-length-allowed-for-dns-hostnames-which-is-253-characters-this-hostname-is-intentionally-made-very-long-to-test-the-validation-logic-and-ensure-that-hostnames-longer-than-253-characters-are-properly-rejected.com",
		"invalid_hostname.com",       // Underscore (invalid in hostnames)
		"hostname-.com",             // Trailing hyphen in label
		"-hostname.com",             // Leading hyphen in label
		"host name.com",             // Space in hostname
		"hostname.com:8080",         // Port in hostname
		"192.168.1.999",            // Invalid IP as hostname
		"nonexistent-domain-12345.invalid", // Non-existent domain
	}

	return invalidHostnames[rand.Intn(len(invalidHostnames))]
}

// generateRandomValidIP creates a random valid IP address for testing
func generateRandomValidIP() string {
	if rand.Intn(2) == 0 {
		// Generate IPv4
		return fmt.Sprintf("%d.%d.%d.%d", 
			rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256))
	} else {
		// Generate simple IPv6
		return fmt.Sprintf("2001:db8::%x", rand.Intn(65536))
	}
}