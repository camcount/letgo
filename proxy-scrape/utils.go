package proxy

import (
	"fmt"
)

// isValidPort checks if a port number is valid
func isValidPort(port string) bool {
	var portNum int
	_, err := fmt.Sscanf(port, "%d", &portNum)
	return err == nil && portNum > 0 && portNum <= 65535
}

// RemoveDuplicates removes duplicate proxies from a slice
func RemoveDuplicates(proxies []ProxyResult) []ProxyResult {
	seen := make(map[string]bool)
	var unique []ProxyResult

	for _, proxy := range proxies {
		key := fmt.Sprintf("%s://%s:%s", proxy.Protocol, proxy.Host, proxy.Port)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, proxy)
		}
	}

	return unique
}

// FormatProxy returns the proxy in standard format
func (pr *ProxyResult) FormatProxy() string {
	return fmt.Sprintf("%s://%s:%s", pr.Protocol, pr.Host, pr.Port)
}
