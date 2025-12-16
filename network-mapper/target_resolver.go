package networkmapper

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// DefaultTargetResolver implements the TargetResolver interface
type DefaultTargetResolver struct{}

// NewTargetResolver creates a new DefaultTargetResolver
func NewTargetResolver() *DefaultTargetResolver {
	return &DefaultTargetResolver{}
}

// ResolveTargets resolves and expands target specifications
func (tr *DefaultTargetResolver) ResolveTargets(targets []string) ([]NetworkTarget, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets provided")
	}

	var resolvedTargets []NetworkTarget

	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		networkTarget, err := tr.resolveTarget(target)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve target '%s': %w", target, err)
		}

		resolvedTargets = append(resolvedTargets, networkTarget)
	}

	return resolvedTargets, nil
}

// resolveTarget resolves a single target specification
func (tr *DefaultTargetResolver) resolveTarget(target string) (NetworkTarget, error) {
	// Check if it's a CIDR range
	if strings.Contains(target, "/") {
		return tr.resolveCIDRTarget(target)
	}

	// Check if it's an IP address
	if ip := net.ParseIP(target); ip != nil {
		return NetworkTarget{
			Original: target,
			IPs:      []net.IP{ip},
			Hostname: "",
		}, nil
	}

	// Check if it's an IP range (e.g., 192.168.1.1-10)
	if strings.Contains(target, "-") {
		return tr.resolveIPRange(target)
	}

	// Assume it's a hostname and resolve it
	return tr.resolveHostnameTarget(target)
}

// resolveCIDRTarget resolves a CIDR range target
func (tr *DefaultTargetResolver) resolveCIDRTarget(target string) (NetworkTarget, error) {
	ips, err := tr.ExpandCIDR(target)
	if err != nil {
		return NetworkTarget{}, err
	}

	var netIPs []net.IP
	for _, ipStr := range ips {
		if ip := net.ParseIP(ipStr); ip != nil {
			netIPs = append(netIPs, ip)
		}
	}

	return NetworkTarget{
		Original: target,
		IPs:      netIPs,
		Hostname: "",
	}, nil
}

// resolveIPRange resolves an IP range (e.g., 192.168.1.1-10)
func (tr *DefaultTargetResolver) resolveIPRange(target string) (NetworkTarget, error) {
	parts := strings.Split(target, "-")
	if len(parts) != 2 {
		return NetworkTarget{}, fmt.Errorf("invalid IP range format: %s", target)
	}

	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	if startIP == nil {
		return NetworkTarget{}, fmt.Errorf("invalid start IP in range: %s", parts[0])
	}

	endStr := strings.TrimSpace(parts[1])

	// Check if end is just a number (last octet)
	if endNum, err := strconv.Atoi(endStr); err == nil {
		return tr.expandLastOctetRange(startIP, endNum)
	}

	// Check if end is a full IP address
	endIP := net.ParseIP(endStr)
	if endIP == nil {
		return NetworkTarget{}, fmt.Errorf("invalid end IP in range: %s", endStr)
	}

	return tr.expandFullIPRange(startIP, endIP)
}

// expandLastOctetRange expands a range where only the last octet changes
func (tr *DefaultTargetResolver) expandLastOctetRange(startIP net.IP, endOctet int) (NetworkTarget, error) {
	if endOctet < 0 || endOctet > 255 {
		return NetworkTarget{}, fmt.Errorf("invalid end octet: %d", endOctet)
	}

	startIP = startIP.To4()
	if startIP == nil {
		return NetworkTarget{}, fmt.Errorf("IPv6 ranges not supported with last octet notation")
	}

	startOctet := int(startIP[3])
	if endOctet < startOctet {
		return NetworkTarget{}, fmt.Errorf("end octet (%d) must be >= start octet (%d)", endOctet, startOctet)
	}

	var ips []net.IP
	baseIP := make(net.IP, 4)
	copy(baseIP, startIP)

	for i := startOctet; i <= endOctet; i++ {
		ip := make(net.IP, 4)
		copy(ip, baseIP)
		ip[3] = byte(i)
		ips = append(ips, ip)
	}

	return NetworkTarget{
		Original: fmt.Sprintf("%s-%d", startIP.String(), endOctet),
		IPs:      ips,
		Hostname: "",
	}, nil
}

// expandFullIPRange expands a range between two full IP addresses
func (tr *DefaultTargetResolver) expandFullIPRange(startIP, endIP net.IP) (NetworkTarget, error) {
	startIP = startIP.To4()
	endIP = endIP.To4()

	if startIP == nil || endIP == nil {
		return NetworkTarget{}, fmt.Errorf("IPv6 ranges not supported")
	}

	// Convert IPs to uint32 for easier comparison
	startInt := ipToUint32(startIP)
	endInt := ipToUint32(endIP)

	if endInt < startInt {
		return NetworkTarget{}, fmt.Errorf("end IP must be >= start IP")
	}

	// Limit range size to prevent memory issues
	const maxRangeSize = 65536 // 2^16
	if endInt-startInt > maxRangeSize {
		return NetworkTarget{}, fmt.Errorf("IP range too large (max %d addresses)", maxRangeSize)
	}

	var ips []net.IP
	for i := startInt; i <= endInt; i++ {
		ip := uint32ToIP(i)
		ips = append(ips, ip)
	}

	return NetworkTarget{
		Original: fmt.Sprintf("%s-%s", startIP.String(), endIP.String()),
		IPs:      ips,
		Hostname: "",
	}, nil
}

// resolveHostnameTarget resolves a hostname target
func (tr *DefaultTargetResolver) resolveHostnameTarget(target string) (NetworkTarget, error) {
	ips, err := tr.ResolveHostname(target)
	if err != nil {
		return NetworkTarget{}, err
	}

	var netIPs []net.IP
	for _, ipStr := range ips {
		if ip := net.ParseIP(ipStr); ip != nil {
			netIPs = append(netIPs, ip)
		}
	}

	return NetworkTarget{
		Original: target,
		IPs:      netIPs,
		Hostname: target,
	}, nil
}

// ExpandCIDR expands a CIDR range to individual IP addresses
func (tr *DefaultTargetResolver) ExpandCIDR(cidr string) ([]string, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR notation: %w", err)
	}

	// Calculate the number of addresses in the range
	ones, bits := ipNet.Mask.Size()
	if bits == 0 {
		return nil, fmt.Errorf("invalid network mask")
	}

	hostBits := bits - ones
	numAddresses := 1 << hostBits

	// Limit CIDR expansion to prevent memory issues
	const maxCIDRSize = 65536 // 2^16
	if numAddresses > maxCIDRSize {
		return nil, fmt.Errorf("CIDR range too large (max %d addresses)", maxCIDRSize)
	}

	// Handle IPv4
	if ipNet.IP.To4() != nil {
		return tr.expandIPv4CIDR(ipNet)
	}

	// Handle IPv6 (basic support)
	return tr.expandIPv6CIDR(ipNet)
}

// expandIPv4CIDR expands an IPv4 CIDR range
func (tr *DefaultTargetResolver) expandIPv4CIDR(ipNet *net.IPNet) ([]string, error) {
	var ips []string

	// Get the network address
	networkIP := ipNet.IP.To4()
	if networkIP == nil {
		return nil, fmt.Errorf("invalid IPv4 network")
	}

	// Calculate mask
	mask := ipNet.Mask
	ones, bits := mask.Size()
	hostBits := bits - ones

	// Convert network IP to uint32
	networkInt := ipToUint32(networkIP)

	// Generate all IPs in the range
	numHosts := 1 << hostBits
	for i := range numHosts {
		ip := uint32ToIP(networkInt + uint32(i))
		ips = append(ips, ip.String())
	}

	return ips, nil
}

// expandIPv6CIDR expands an IPv6 CIDR range (basic implementation)
func (tr *DefaultTargetResolver) expandIPv6CIDR(ipNet *net.IPNet) ([]string, error) {
	// For IPv6, we'll implement a basic version that handles small ranges
	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones

	// Only handle small IPv6 ranges to prevent memory issues
	if hostBits > 16 {
		return nil, fmt.Errorf("IPv6 CIDR range too large (max /112)")
	}

	var ips []string
	numHosts := 1 << hostBits

	// Get the network address
	networkIP := ipNet.IP

	for i := range numHosts {
		ip := make(net.IP, len(networkIP))
		copy(ip, networkIP)

		// Add the host part (simple increment for small ranges)
		carry := i
		for j := len(ip) - 1; j >= 0 && carry > 0; j-- {
			sum := int(ip[j]) + carry
			ip[j] = byte(sum & 0xFF)
			carry = sum >> 8
		}

		ips = append(ips, ip.String())
	}

	return ips, nil
}

// ResolveHostname resolves a hostname to IP addresses
func (tr *DefaultTargetResolver) ResolveHostname(hostname string) ([]string, error) {
	// Validate hostname format
	if !tr.isValidHostname(hostname) {
		return nil, fmt.Errorf("invalid hostname format: %s", hostname)
	}

	// Resolve the hostname
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve hostname '%s': %w", hostname, err)
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

// isValidHostname validates hostname format
func (tr *DefaultTargetResolver) isValidHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 253 {
		return false
	}

	// Basic hostname validation regex
	hostnameRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	return hostnameRegex.MatchString(hostname)
}

// Helper functions for IP conversion
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 + uint32(ip[1])<<16 + uint32(ip[2])<<8 + uint32(ip[3])
}

func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}
