package ddosscanner

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	
	"github.com/letgo/paths"
)

var dataDir = paths.GetDataDir()

// ExtractSiteName extracts a clean site name from URL for file naming
// Returns base domain with dots preserved (e.g., "airportthai.co.th" from "aoportal.airportthai.co.th")
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

	// Extract base domain (e.g., "airportthai.co.th" from "aoportal.airportthai.co.th")
	hostParts := strings.Split(host, ".")
	if len(hostParts) < 2 {
		return sanitizeFilename(host)
	}

	// Get the base domain (last 2 parts for .co.th, .com, etc., or last 3 for .co.uk)
	var baseDomain string
	if len(hostParts) >= 3 {
		// Handle cases like .co.th, .co.uk
		if hostParts[len(hostParts)-2] == "co" {
			baseDomain = strings.Join(hostParts[len(hostParts)-3:], ".")
		} else {
			baseDomain = strings.Join(hostParts[len(hostParts)-2:], ".")
		}
	} else {
		baseDomain = strings.Join(hostParts[len(hostParts)-2:], ".")
	}

	// Keep dots in folder names, but still sanitize for invalid characters
	return sanitizeFolderName(baseDomain)
}

// sanitizeFolderName removes invalid characters for folder names but preserves dots
func sanitizeFolderName(name string) string {
	// Remove invalid characters for folder names (but keep dots)
	invalidChars := regexp.MustCompile(`[<>:"/\\|?*\x00-\x1f]`)
	name = invalidChars.ReplaceAllString(name, "-")

	// Remove multiple consecutive hyphens (but not dots)
	name = regexp.MustCompile(`-+`).ReplaceAllString(name, "-")

	// Trim hyphens from start and end (but not dots)
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
	dir := filepath.Join(dataDir, "ddos-targets")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return os.MkdirAll(dir, 0755)
	}
	return nil
}

// MoveCURLDDOSFile moves cURL-DDOS.txt to ddos-targets folder if it exists in root
func MoveCURLDDOSFile() error {
	sourcePath := "cURL-DDOS.txt"
	targetPath := filepath.Join(dataDir, "ddos-targets", "cURL-DDOS.txt")

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
// This function maintains backward compatibility with flat structure
func ListDDOSTargetFiles() ([]string, error) {
	if err := EnsureDDOSTargetsDir(); err != nil {
		return nil, err
	}

	dir := filepath.Join(dataDir, "ddos-targets")
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

// ListDDOSTargetFolders lists all site folders in ddos-targets directory
func ListDDOSTargetFolders() ([]string, error) {
	if err := EnsureDDOSTargetsDir(); err != nil {
		return nil, err
	}

	dir := filepath.Join(dataDir, "ddos-targets")
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read ddos-targets directory: %w", err)
	}

	var folders []string
	for _, file := range files {
		if file.IsDir() {
			folders = append(folders, file.Name())
		}
	}

	return folders, nil
}

// ListDDOSTargetFilesInFolder lists all .txt files in a specific site folder
func ListDDOSTargetFilesInFolder(folderName string) ([]string, error) {
	if err := EnsureDDOSTargetsDir(); err != nil {
		return nil, err
	}

	folderPath := filepath.Join(dataDir, "ddos-targets", folderName)
	files, err := os.ReadDir(folderPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read folder %s: %w", folderName, err)
	}

	var txtFiles []string
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(strings.ToLower(file.Name()), ".txt") {
			txtFiles = append(txtFiles, filepath.Join(folderPath, file.Name()))
		}
	}

	return txtFiles, nil
}

// GetFilenamePatternForAttackMode returns the filename pattern for a given attack mode
func GetFilenamePatternForAttackMode(attackMode string) string {
	switch attackMode {
	case "rudy":
		return "rudy-"
	case "http2-stream-flood":
		return "http2-stream-flood-"
	case "flood":
		return "flood-"
	case "slowloris":
		return "slowloris-"
	case "mixed":
		return "mixed-"
	default:
		return ""
	}
}

// GetFilesMatchingTemplate finds files in a folder that match the template's attack mode
func GetFilesMatchingTemplate(folderPath string, attackMode string) ([]string, error) {
	files, err := os.ReadDir(folderPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read folder %s: %w", folderPath, err)
	}

	pattern := GetFilenamePatternForAttackMode(attackMode)
	if pattern == "" {
		// If no pattern, return all .txt files
		var txtFiles []string
		for _, file := range files {
			if !file.IsDir() && strings.HasSuffix(strings.ToLower(file.Name()), ".txt") {
				txtFiles = append(txtFiles, filepath.Join(folderPath, file.Name()))
			}
		}
		return txtFiles, nil
	}

	var matchingFiles []string
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(strings.ToLower(file.Name()), ".txt") {
			if strings.HasPrefix(strings.ToLower(file.Name()), pattern) {
				matchingFiles = append(matchingFiles, filepath.Join(folderPath, file.Name()))
			}
		}
	}

	return matchingFiles, nil
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

// ExtractHostname extracts the full hostname (domain + subdomain) from a URL
// Returns the full hostname for folder naming
// For example:
// - "https://www.example.com" -> "www.example.com"
// - "https://api.example.com" -> "api.example.com"
// - "https://test.example.com" -> "test.example.com"
// - "https://example.com" -> "example.com"
func ExtractHostname(targetURL string) string {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return ""
	}

	host := parsed.Hostname()
	if host == "" {
		return ""
	}

	// Remove port if present
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	host = strings.ToLower(host)
	
	// Return the full hostname, sanitized for folder name
	return sanitizeFolderName(host)
}

