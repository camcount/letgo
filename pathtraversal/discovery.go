package pathtraversal

import (
	"net"
	"net/url"
	"strings"
)

// DiscoverParameters automatically discovers parameters from a URL
func DiscoverParameters(targetURL string) []string {
	discoveredParams := make(map[string]bool)

	// Parse the URL
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return []string{}
	}

	// Extract query parameters
	queryParams := parsedURL.Query()
	for param := range queryParams {
		discoveredParams[param] = true
	}

	// Extract path segments that look like they could be parameters
	pathSegments := strings.Split(parsedURL.Path, "/")
	for _, segment := range pathSegments {
		if segment == "" || segment == parsedURL.Host {
			continue
		}

		// Check if segment looks like an ID or filename
		if looksLikeParameter(segment) {
			discoveredParams[segment] = true
		}
	}

	// Add common parameters that might not be in the URL yet
	for _, param := range CommonParameters() {
		// Only add if they look likely based on common usage
		if strings.Contains(strings.ToLower(targetURL), strings.ToLower(param)) {
			discoveredParams[param] = true
		}
	}

	// If URL has no parameters, suggest common ones
	if len(discoveredParams) == 0 {
		suggested := suggestParameters(targetURL)
		for _, param := range suggested {
			discoveredParams[param] = true
		}
	}

	// Convert map to slice
	result := make([]string, 0, len(discoveredParams))
	for param := range discoveredParams {
		result = append(result, param)
	}

	return result
}

// looksLikeParameter determines if a string could be a parameter name/value
func looksLikeParameter(segment string) bool {
	// Remove leading/trailing whitespace
	segment = strings.TrimSpace(segment)

	if len(segment) == 0 {
		return false
	}

	// Skip if it looks like a file extension
	if strings.Contains(segment, ".") && hasCommonExtension(segment) {
		return false
	}

	// Skip common non-parameter segments
	if skipSegment(segment) {
		return false
	}

	// Check if it's numeric (could be ID)
	if isNumeric(segment) {
		return true
	}

	// Check if it looks like a slug/identifier
	if isValidSlug(segment) {
		return true
	}

	return false
}

// hasCommonExtension checks if string ends with common web extensions
func hasCommonExtension(s string) bool {
	extensions := []string{".html", ".php", ".asp", ".aspx", ".jsp", ".js", ".css", ".png", ".jpg", ".gif", ".pdf", ".txt", ".xml", ".json"}
	for _, ext := range extensions {
		if strings.HasSuffix(strings.ToLower(s), ext) {
			return true
		}
	}
	return false
}

// skipSegment returns true if segment should be skipped
func skipSegment(segment string) bool {
	skip := []string{
		"api", "v1", "v2", "v3", "users", "posts", "items",
		"admin", "dashboard", "home", "index",
		"localhost", "127.0.0.1", "0.0.0.0",
	}

	lowerSegment := strings.ToLower(segment)
	for _, s := range skip {
		if lowerSegment == s {
			return false // Don't skip, these can have parameters
		}
	}

	return false
}

// isNumeric checks if string contains only digits
func isNumeric(s string) bool {
	for _, char := range s {
		if char < '0' || char > '9' {
			return false
		}
	}
	return len(s) > 0
}

// isValidSlug checks if string looks like a URL slug
func isValidSlug(s string) bool {
	if len(s) == 0 || len(s) > 255 {
		return false
	}

	// Must contain only alphanumeric, hyphens, underscores
	for _, char := range s {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '-' || char == '_') {
			return false
		}
	}

	return true
}

// suggestParameters suggests common parameters based on URL analysis
func suggestParameters(targetURL string) []string {
	suggested := []string{}

	// Always suggest common file/path parameters
	baseParams := []string{"file", "path", "id", "page", "include", "load"}

	// Check if URL contains certain keywords
	lowerURL := strings.ToLower(targetURL)

	if strings.Contains(lowerURL, "user") {
		baseParams = append(baseParams, "user_id", "username", "profile")
	}
	if strings.Contains(lowerURL, "post") {
		baseParams = append(baseParams, "post_id", "slug")
	}
	if strings.Contains(lowerURL, "article") {
		baseParams = append(baseParams, "article_id", "slug")
	}
	if strings.Contains(lowerURL, "product") {
		baseParams = append(baseParams, "product_id", "sku")
	}
	if strings.Contains(lowerURL, "page") {
		baseParams = append(baseParams, "page_id", "slug")
	}
	if strings.Contains(lowerURL, "image") || strings.Contains(lowerURL, "img") {
		baseParams = append(baseParams, "image_id", "src", "image_path")
	}
	if strings.Contains(lowerURL, "download") {
		baseParams = append(baseParams, "file", "filepath", "filename")
	}

	// Remove duplicates
	seen := make(map[string]bool)
	for _, param := range baseParams {
		if !seen[param] {
			suggested = append(suggested, param)
			seen[param] = true
		}
	}

	return suggested
}

// ExtractHostInfo gets domain and IP info from URL
func ExtractHostInfo(targetURL string) (hostname string, isIP bool) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return "", false
	}

	host := parsedURL.Hostname()
	if host == "" {
		return "", false
	}

	// Check if it's an IP address
	ip := net.ParseIP(host)
	if ip != nil {
		return host, true
	}

	return host, false
}

// NormalizeURL ensures URL has proper format
func NormalizeURL(targetURL string) string {
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "http://" + targetURL
	}
	return targetURL
}
