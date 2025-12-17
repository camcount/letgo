package networkmapper

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// DefaultIPResolver implements the IPResolver interface
type DefaultIPResolver struct {
	timeout     time.Duration
	maxRetries  int
	dnsServers  []string
	asnDatabase ASNDatabase
	geoDatabase GeoDatabase
}

// ASNDatabase interface for ASN lookups
type ASNDatabase interface {
	LookupASN(ip string) (ASNInfo, error)
}

// GeoDatabase interface for geolocation lookups
type GeoDatabase interface {
	LookupGeo(ip string) (GeoInfo, error)
}

// ASNInfo contains ASN information
type ASNInfo struct {
	ASN          string
	Organization string
	ISP          string
	CloudPlatform string
	HostingProvider string
}

// GeoInfo contains geolocation information
type GeoInfo struct {
	Country  string
	Region   string
	City     string
	Timezone string
}

// NewIPResolver creates a new DefaultIPResolver with default settings
func NewIPResolver() *DefaultIPResolver {
	return &DefaultIPResolver{
		timeout:     2 * time.Second, // Reduced timeout for testing
		maxRetries:  1,               // Reduced retries for testing
		dnsServers:  []string{"8.8.8.8", "1.1.1.1", "208.67.222.222"}, // Google, Cloudflare, OpenDNS
		asnDatabase: NewMockASNDatabase(),
		geoDatabase: NewMockGeoDatabase(),
	}
}

// NewIPResolverWithOptions creates a new DefaultIPResolver with custom options
func NewIPResolverWithOptions(timeout time.Duration, maxRetries int, dnsServers []string) *DefaultIPResolver {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if maxRetries <= 0 {
		maxRetries = 3
	}
	if len(dnsServers) == 0 {
		dnsServers = []string{"8.8.8.8", "1.1.1.1"}
	}

	return &DefaultIPResolver{
		timeout:     timeout,
		maxRetries:  maxRetries,
		dnsServers:  dnsServers,
		asnDatabase: NewMockASNDatabase(),
		geoDatabase: NewMockGeoDatabase(),
	}
}

// ResolveHostname resolves a hostname to IP addresses with IPv4 and IPv6 support
func (r *DefaultIPResolver) ResolveHostname(ctx context.Context, hostname string) ([]ResolvedIP, error) {
	options := ResolveOptions{
		IncludeIPv4: true,
		IncludeIPv6: true,
		Timeout:     r.timeout,
		Retries:     r.maxRetries,
	}
	return r.ResolveHostnameWithOptions(ctx, hostname, options)
}

// ResolveHostnameWithOptions resolves hostname with specific options
func (r *DefaultIPResolver) ResolveHostnameWithOptions(ctx context.Context, hostname string, options ResolveOptions) ([]ResolvedIP, error) {
	if hostname == "" {
		return nil, fmt.Errorf("hostname cannot be empty")
	}

	// Validate hostname format
	if !r.isValidHostname(hostname) {
		return nil, fmt.Errorf("invalid hostname format: %s", hostname)
	}

	// Check if it's already an IP address
	if ip := net.ParseIP(hostname); ip != nil {
		ipType := "IPv4"
		if ip.To4() == nil {
			ipType = "IPv6"
		}
		
		// Check if we should include this IP type
		if (ipType == "IPv4" && !options.IncludeIPv4) || (ipType == "IPv6" && !options.IncludeIPv6) {
			return []ResolvedIP{}, nil
		}

		return []ResolvedIP{
			{
				IP:         hostname,
				Type:       ipType,
				TTL:        0,
				Source:     "direct",
				Hostname:   hostname,
				ResolvedAt: time.Now(),
			},
		}, nil
	}

	// Set up context with timeout
	if options.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, options.Timeout)
		defer cancel()
	}

	var resolvedIPs []ResolvedIP
	var lastErr error

	// Attempt resolution with retries
	for attempt := 0; attempt <= options.Retries; attempt++ {
		ips, err := r.performDNSLookup(ctx, hostname)
		if err == nil {
			// Filter IPs based on options
			for _, ip := range ips {
				ipAddr := net.ParseIP(ip)
				if ipAddr == nil {
					continue
				}

				ipType := "IPv4"
				if ipAddr.To4() == nil {
					ipType = "IPv6"
				}

				// Check if we should include this IP type
				if (ipType == "IPv4" && !options.IncludeIPv4) || (ipType == "IPv6" && !options.IncludeIPv6) {
					continue
				}

				resolvedIPs = append(resolvedIPs, ResolvedIP{
					IP:         ip,
					Type:       ipType,
					TTL:        0, // TTL not available from standard library
					Source:     "dns",
					Hostname:   hostname,
					ResolvedAt: time.Now(),
				})
			}

			if len(resolvedIPs) > 0 {
				return resolvedIPs, nil
			}
		}

		lastErr = err

		// Wait before retry (except on last attempt)
		if attempt < options.Retries {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt+1) * 100 * time.Millisecond):
				// Continue to next attempt
			}
		}
	}

	if len(resolvedIPs) == 0 && lastErr != nil {
		return nil, fmt.Errorf("failed to resolve hostname '%s' after %d attempts: %w", hostname, options.Retries+1, lastErr)
	}

	return resolvedIPs, nil
}

// performDNSLookup performs the actual DNS lookup
func (r *DefaultIPResolver) performDNSLookup(ctx context.Context, hostname string) ([]string, error) {
	// Use the standard library for DNS resolution
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return nil, err
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for hostname: %s", hostname)
	}

	var ipStrings []string
	for _, ip := range ips {
		ipStrings = append(ipStrings, ip.String())
	}

	return ipStrings, nil
}

// ReverseLookup performs reverse DNS lookup on an IP address
func (r *DefaultIPResolver) ReverseLookup(ctx context.Context, ip string) ([]string, error) {
	if ip == "" {
		return nil, fmt.Errorf("IP address cannot be empty")
	}

	// Validate IP address
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	// Set up context with timeout
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	var hostnames []string
	var lastErr error

	// Attempt reverse lookup with retries
	for attempt := 0; attempt <= r.maxRetries; attempt++ {
		names, err := net.LookupAddr(ip)
		if err == nil && len(names) > 0 {
			// Clean up hostnames (remove trailing dots)
			for _, name := range names {
				cleanName := strings.TrimSuffix(name, ".")
				if cleanName != "" {
					hostnames = append(hostnames, cleanName)
				}
			}
			return hostnames, nil
		}

		lastErr = err

		// Wait before retry (except on last attempt)
		if attempt < r.maxRetries {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt+1) * 100 * time.Millisecond):
				// Continue to next attempt
			}
		}
	}

	if lastErr != nil {
		return nil, fmt.Errorf("failed to perform reverse DNS lookup for IP '%s': %w", ip, lastErr)
	}

	return hostnames, nil
}

// GetIPInfo retrieves geolocation and ASN information for an IP address
func (r *DefaultIPResolver) GetIPInfo(ctx context.Context, ip string) (IPInfo, error) {
	if ip == "" {
		return IPInfo{}, fmt.Errorf("IP address cannot be empty")
	}

	// Validate IP address
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return IPInfo{}, fmt.Errorf("invalid IP address: %s", ip)
	}

	info := IPInfo{
		IP:       ip,
		Metadata: make(map[string]string),
	}

	// Get ASN information
	if r.asnDatabase != nil {
		asnInfo, err := r.asnDatabase.LookupASN(ip)
		if err == nil {
			info.ASN = asnInfo.ASN
			info.Organization = asnInfo.Organization
			info.ISP = asnInfo.ISP
			info.CloudPlatform = asnInfo.CloudPlatform
			info.HostingProvider = asnInfo.HostingProvider
		} else {
			info.Metadata["asn_error"] = err.Error()
		}
	}

	// Get geolocation information
	if r.geoDatabase != nil {
		geoInfo, err := r.geoDatabase.LookupGeo(ip)
		if err == nil {
			info.Country = geoInfo.Country
			info.Region = geoInfo.Region
			info.City = geoInfo.City
			info.Timezone = geoInfo.Timezone
		} else {
			info.Metadata["geo_error"] = err.Error()
		}
	}

	return info, nil
}

// isValidHostname validates hostname format
func (r *DefaultIPResolver) isValidHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 253 {
		return false
	}

	// Check for valid characters and format
	if strings.HasPrefix(hostname, ".") || strings.HasSuffix(hostname, ".") {
		return false
	}

	labels := strings.Split(hostname, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return false
		}

		// Check label format
		for i, r := range label {
			if i == 0 || i == len(label)-1 {
				// First and last character must be alphanumeric
				if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
					return false
				}
			} else {
				// Middle characters can be alphanumeric or hyphen
				if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-') {
					return false
				}
			}
		}
	}

	return true
}

// Mock implementations for testing and basic functionality

// MockASNDatabase provides basic ASN information
type MockASNDatabase struct {
	asnData map[string]ASNInfo
}

// NewMockASNDatabase creates a new mock ASN database
func NewMockASNDatabase() *MockASNDatabase {
	return &MockASNDatabase{
		asnData: map[string]ASNInfo{
			// Google
			"8.8.8.8": {
				ASN:          "AS15169",
				Organization: "Google LLC",
				ISP:          "Google",
				CloudPlatform: "Google Cloud",
				HostingProvider: "Google",
			},
			"8.8.4.4": {
				ASN:          "AS15169",
				Organization: "Google LLC",
				ISP:          "Google",
				CloudPlatform: "Google Cloud",
				HostingProvider: "Google",
			},
			// Cloudflare
			"1.1.1.1": {
				ASN:          "AS13335",
				Organization: "Cloudflare, Inc.",
				ISP:          "Cloudflare",
				CloudPlatform: "Cloudflare",
				HostingProvider: "Cloudflare",
			},
			"1.0.0.1": {
				ASN:          "AS13335",
				Organization: "Cloudflare, Inc.",
				ISP:          "Cloudflare",
				CloudPlatform: "Cloudflare",
				HostingProvider: "Cloudflare",
			},
		},
	}
}

// LookupASN performs ASN lookup
func (db *MockASNDatabase) LookupASN(ip string) (ASNInfo, error) {
	if info, exists := db.asnData[ip]; exists {
		return info, nil
	}

	// Return generic information for unknown IPs
	return ASNInfo{
		ASN:          "AS0",
		Organization: "Unknown",
		ISP:          "Unknown",
		CloudPlatform: "",
		HostingProvider: "Unknown",
	}, nil
}

// MockGeoDatabase provides basic geolocation information
type MockGeoDatabase struct {
	geoData map[string]GeoInfo
}

// NewMockGeoDatabase creates a new mock geo database
func NewMockGeoDatabase() *MockGeoDatabase {
	return &MockGeoDatabase{
		geoData: map[string]GeoInfo{
			// Google DNS
			"8.8.8.8": {
				Country:  "US",
				Region:   "California",
				City:     "Mountain View",
				Timezone: "America/Los_Angeles",
			},
			"8.8.4.4": {
				Country:  "US",
				Region:   "California",
				City:     "Mountain View",
				Timezone: "America/Los_Angeles",
			},
			// Cloudflare DNS
			"1.1.1.1": {
				Country:  "US",
				Region:   "California",
				City:     "San Francisco",
				Timezone: "America/Los_Angeles",
			},
			"1.0.0.1": {
				Country:  "US",
				Region:   "California",
				City:     "San Francisco",
				Timezone: "America/Los_Angeles",
			},
		},
	}
}

// LookupGeo performs geolocation lookup
func (db *MockGeoDatabase) LookupGeo(ip string) (GeoInfo, error) {
	if info, exists := db.geoData[ip]; exists {
		return info, nil
	}

	// Return generic information for unknown IPs
	return GeoInfo{
		Country:  "Unknown",
		Region:   "Unknown",
		City:     "Unknown",
		Timezone: "UTC",
	}, nil
}