package proxy

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	
	"github.com/letgo/paths"
)

var dataDir = paths.GetDataDir()

// ReadProxiesFromFile reads proxies from a file and returns them as ProxyResult slice
func ReadProxiesFromFile(filename string) ([]ProxyResult, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var proxies []ProxyResult
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse format: protocol://host:port
		parts := strings.SplitN(line, "://", 2)
		if len(parts) != 2 {
			continue
		}

		protocol := parts[0]
		hostPort := parts[1]

		hostPortParts := strings.Split(hostPort, ":")
		if len(hostPortParts) != 2 {
			continue
		}

		proxies = append(proxies, ProxyResult{
			Protocol: protocol,
			Host:     hostPortParts[0],
			Port:     hostPortParts[1],
			IsValid:  false,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan file: %w", err)
	}

	return proxies, nil
}

// WriteProxiesToFile writes proxies to a file, overwriting existing content
func WriteProxiesToFile(proxies []ProxyResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := "# Proxy List - Scraped Proxies\n"
	header += "# Format: protocol://host:port\n"
	header += "# Total: " + fmt.Sprintf("%d", len(proxies)) + "\n\n"
	if _, err := writer.WriteString(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Write proxies
	for _, p := range proxies {
		if _, err := writer.WriteString(p.FormatProxy() + "\n"); err != nil {
			return fmt.Errorf("failed to write proxy: %w", err)
		}
	}

	return nil
}

// BackupAndPrepareProxies copies existing validated proxies from proxy.txt to raw-proxy.txt and clears proxy.txt
// Returns the number of backed up proxies
func BackupAndPrepareProxies() (int, error) {
	// Ensure proxy directory exists
	proxyDir := filepath.Join(dataDir, "proxy")
	if err := os.MkdirAll(proxyDir, 0755); err != nil {
		return 0, fmt.Errorf("failed to create proxy directory: %w", err)
	}

	proxyFilePath := filepath.Join(proxyDir, "proxy.txt")
	rawProxyFilePath := filepath.Join(proxyDir, "raw-proxy.txt")

	// Check if proxy.txt exists
	if _, err := os.Stat(proxyFilePath); os.IsNotExist(err) {
		// File doesn't exist, nothing to backup
		return 0, nil
	}

	// Read validated proxies from proxy.txt
	validProxies, err := ReadProxiesFromFile(proxyFilePath)
	if err != nil {
		return 0, fmt.Errorf("failed to read validated proxies: %w", err)
	}

	if len(validProxies) == 0 {
		// No proxies to backup
		return 0, nil
	}

	// Read existing proxies from raw-proxy.txt (if it exists)
	var rawProxies []ProxyResult
	if _, err := os.Stat(rawProxyFilePath); err == nil {
		rawProxies, err = ReadProxiesFromFile(rawProxyFilePath)
		if err != nil {
			return 0, fmt.Errorf("failed to read raw proxies: %w", err)
		}
	}

	// Combine both lists
	combinedProxies := append(validProxies, rawProxies...)

	// Remove duplicates
	deduplicatedProxies := RemoveDuplicates(combinedProxies)

	// Write combined and deduplicated list to raw-proxy.txt
	if err := WriteProxiesToFile(deduplicatedProxies, rawProxyFilePath); err != nil {
		return 0, fmt.Errorf("failed to write to raw-proxy.txt: %w", err)
	}

	// Clear proxy.txt by creating a new empty file with just header
	if err := clearProxyFile(proxyFilePath); err != nil {
		return 0, fmt.Errorf("failed to clear proxy.txt: %w", err)
	}

	return len(validProxies), nil
}

// MergeAndDeduplicateProxies reads proxies from raw-proxy.txt, removes duplicates, and writes back
// Returns the number of unique proxies after deduplication
func MergeAndDeduplicateProxies() (int, int, error) {
	rawProxyFilePath := filepath.Join(dataDir, "proxy", "raw-proxy.txt")

	// Check if raw-proxy.txt exists
	if _, err := os.Stat(rawProxyFilePath); os.IsNotExist(err) {
		return 0, 0, fmt.Errorf("raw-proxy.txt not found")
	}

	// Read all proxies from raw-proxy.txt
	proxies, err := ReadProxiesFromFile(rawProxyFilePath)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to read proxies: %w", err)
	}

	if len(proxies) == 0 {
		return 0, 0, nil
	}

	originalCount := len(proxies)

	// Remove duplicates
	deduplicatedProxies := RemoveDuplicates(proxies)
	uniqueCount := len(deduplicatedProxies)

	// Write back to raw-proxy.txt
	if err := WriteProxiesToFile(deduplicatedProxies, rawProxyFilePath); err != nil {
		return originalCount, uniqueCount, fmt.Errorf("failed to write deduplicated proxies: %w", err)
	}

	return originalCount, uniqueCount, nil
}

// clearProxyFile initializes the proxy file with header
func clearProxyFile(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Write header
	header := "# Proxy List - Validated Working Proxies\n"
	header += "# Format: protocol://host:port\n"
	header += "# Proxies are written in real-time as they are validated\n\n"
	if _, err := file.WriteString(header); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	return nil
}
