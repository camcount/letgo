package ddosscanner

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ExtractSiteName extracts a clean site name from URL for file naming
func ExtractSiteName(targetURL string) string {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		// Fallback: use the URL as-is, sanitize it
		return sanitizeFilename(targetURL)
	}

	host := parsed.Hostname()
	if host == "" {
		return sanitizeFilename(targetURL)
	}

	// Remove port if present
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// Replace dots with hyphens
	host = strings.ReplaceAll(host, ".", "-")

	// Remove protocol prefix if somehow included
	host = strings.TrimPrefix(host, "http-")
	host = strings.TrimPrefix(host, "https-")

	return sanitizeFilename(host)
}

// sanitizeFilename removes invalid characters for filenames
func sanitizeFilename(name string) string {
	// Remove invalid characters
	invalidChars := regexp.MustCompile(`[<>:"/\\|?*\x00-\x1f]`)
	name = invalidChars.ReplaceAllString(name, "-")

	// Remove multiple consecutive hyphens
	name = regexp.MustCompile(`-+`).ReplaceAllString(name, "-")

	// Trim hyphens from start and end
	name = strings.Trim(name, "-")

	// Limit length
	if len(name) > 100 {
		name = name[:100]
	}

	// Ensure it's not empty
	if name == "" {
		name = "target"
	}

	return name
}

// GenerateFileName generates filename in format [method]-[site-name].txt
func GenerateFileName(method string, siteName string) string {
	method = sanitizeFilename(method)
	return fmt.Sprintf("%s-%s.txt", method, siteName)
}

// EnsureDDOSTargetsDir ensures the ddos-targets directory exists
func EnsureDDOSTargetsDir() error {
	dir := "ddos-targets"
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return os.Mkdir(dir, 0755)
	}
	return nil
}

// MoveCURLDDOSFile moves cURL-DDOS.txt to ddos-targets folder if it exists in root
func MoveCURLDDOSFile() error {
	sourcePath := "cURL-DDOS.txt"
	targetPath := filepath.Join("ddos-targets", "cURL-DDOS.txt")

	// Check if source exists
	if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
		return nil // File doesn't exist, nothing to move
	}

	// Check if target already exists
	if _, err := os.Stat(targetPath); err == nil {
		return nil // Target already exists, don't overwrite
	}

	// Ensure target directory exists
	if err := EnsureDDOSTargetsDir(); err != nil {
		return fmt.Errorf("failed to create ddos-targets directory: %w", err)
	}

	// Move the file
	return os.Rename(sourcePath, targetPath)
}

// ListDDOSTargetFiles lists all .txt files in ddos-targets directory
func ListDDOSTargetFiles() ([]string, error) {
	if err := EnsureDDOSTargetsDir(); err != nil {
		return nil, err
	}

	dir := "ddos-targets"
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read ddos-targets directory: %w", err)
	}

	var txtFiles []string
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(strings.ToLower(file.Name()), ".txt") {
			txtFiles = append(txtFiles, filepath.Join(dir, file.Name()))
		}
	}

	return txtFiles, nil
}

// NormalizeURL normalizes a URL for comparison
func NormalizeURL(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	// Normalize scheme
	if parsed.Scheme == "" {
		parsed.Scheme = "https"
	}

	// Normalize path
	if parsed.Path == "" {
		parsed.Path = "/"
	}

	// Remove fragment
	parsed.Fragment = ""

	// Remove query if empty
	if parsed.RawQuery == "" {
		parsed.RawQuery = ""
	}

	return parsed.String(), nil
}

// IsSameDomain checks if two URLs are from the same domain
func IsSameDomain(url1, url2 string) bool {
	u1, err1 := url.Parse(url1)
	u2, err2 := url.Parse(url2)

	if err1 != nil || err2 != nil {
		return false
	}

	return u1.Hostname() == u2.Hostname()
}

// IsSameDomainOrSubdomain checks if a URL belongs to the same domain or is a subdomain
// For example, if origin is "suvarnabhumi.airportthai.co.th", it will match:
// - suvarnabhumi.airportthai.co.th (exact match)
// - www.airportthai.co.th (subdomain)
// - api.airportthai.co.th (subdomain)
// But will NOT match:
// - google.com (different domain)
// - airportthai.com (different TLD)
func IsSameDomainOrSubdomain(targetURL, originURL string) bool {
	targetParsed, err1 := url.Parse(targetURL)
	originParsed, err2 := url.Parse(originURL)

	if err1 != nil || err2 != nil {
		return false
	}

	targetHost := strings.ToLower(targetParsed.Hostname())
	originHost := strings.ToLower(originParsed.Hostname())

	// Exact match
	if targetHost == originHost {
		return true
	}

	// Check if target is a subdomain of origin or vice versa
	// Extract base domain (e.g., "airportthai.co.th" from "suvarnabhumi.airportthai.co.th")
	originParts := strings.Split(originHost, ".")
	if len(originParts) < 2 {
		return false
	}

	// Get the base domain (last 2 parts for .co.th, .com, etc., or last 3 for .co.uk)
	baseDomain := ""
	if len(originParts) >= 3 {
		// Handle cases like .co.th, .co.uk
		if originParts[len(originParts)-2] == "co" {
			baseDomain = strings.Join(originParts[len(originParts)-3:], ".")
		} else {
			baseDomain = strings.Join(originParts[len(originParts)-2:], ".")
		}
	} else {
		baseDomain = strings.Join(originParts[len(originParts)-2:], ".")
	}

	// Check if target host ends with the base domain
	return strings.HasSuffix(targetHost, "."+baseDomain) || targetHost == baseDomain
}

