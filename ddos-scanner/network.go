package ddosscanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// NetworkRequest represents a captured network request
type NetworkRequest struct {
	URL        string
	Method     string
	StatusCode int
	Headers    http.Header
	Body       []byte
	Timestamp  time.Time
	Type       string // "html", "js", "css", "image", "xhr", "fetch", "api", etc.
}

// NetworkInterceptor captures all HTTP requests made during page load
type NetworkInterceptor struct {
	requests    []NetworkRequest
	requestsMu  sync.Mutex
	baseURL     *url.URL
	client      *http.Client
	userAgent   string
	customHeaders map[string]string
}

// NewNetworkInterceptor creates a new network interceptor
func NewNetworkInterceptor(baseURL string, userAgent string, customHeaders map[string]string, timeout time.Duration) (*NetworkInterceptor, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid base URL: %w", err)
	}

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Follow redirects but limit to 5
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			return nil
		},
	}

	return &NetworkInterceptor{
		requests:      make([]NetworkRequest, 0),
		baseURL:       parsedURL,
		client:        client,
		userAgent:     userAgent,
		customHeaders: customHeaders,
	}, nil
}

// makeRequestAndCapture makes an HTTP request and captures it
func (ni *NetworkInterceptor) makeRequestAndCapture(ctx context.Context, method, urlStr string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, urlStr, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", ni.userAgent)
	if ni.customHeaders != nil {
		for k, v := range ni.customHeaders {
			req.Header.Set(k, v)
		}
	}

	// Capture request before making it
	reqType := ni.detectRequestType(urlStr, method)
	startTime := time.Now()

	// Make the request
	resp, err := ni.client.Do(req)
	responseTime := time.Since(startTime)

	// Capture the request/response
	ni.requestsMu.Lock()
	netReq := NetworkRequest{
		URL:       urlStr,
		Method:    method,
		Timestamp: startTime,
		Type:      reqType,
	}
	if resp != nil {
		netReq.StatusCode = resp.StatusCode
		netReq.Headers = resp.Header.Clone()
		
		// Read body (limit to 1MB) - but we need to be careful not to consume it
		if resp.Body != nil {
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
			netReq.Body = bodyBytes
			// Recreate the body reader since we consumed it
			resp.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
		}
	}
	ni.requests = append(ni.requests, netReq)
	ni.requestsMu.Unlock()

	_ = responseTime // Can be used for logging if needed

	return resp, err
}

// LoadPageAndCaptureRequests loads a page and captures all network requests
func (ni *NetworkInterceptor) LoadPageAndCaptureRequests(ctx context.Context, targetURL string) ([]NetworkRequest, error) {
	// Clear previous requests
	ni.requestsMu.Lock()
	ni.requests = make([]NetworkRequest, 0)
	ni.requestsMu.Unlock()

	// Load the main page (this will be captured)
	resp, err := ni.makeRequestAndCapture(ctx, "GET", targetURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Get the HTML from the captured request body
	var html string
	ni.requestsMu.Lock()
	if len(ni.requests) > 0 {
		// Get the last request (the main page)
		lastReq := ni.requests[len(ni.requests)-1]
		html = string(lastReq.Body)
	}
	ni.requestsMu.Unlock()

	// If we don't have the body, read it from response
	if html == "" {
		htmlBytes, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB limit
		if err != nil && err != io.EOF {
			return nil, err
		}
		html = string(htmlBytes)
	}

	// Extract and load all assets
	ni.loadAllAssets(ctx, targetURL, html)

	// Extract API endpoints from JavaScript files
	apiEndpoints := ni.extractAPIEndpointsFromJS(ctx, html, targetURL)
	for _, endpoint := range apiEndpoints {
		// Only add if it's from the same domain
		if IsSameDomainOrSubdomain(endpoint.URL, targetURL) {
			ni.addRequestIfNew(endpoint.URL, endpoint.Method, endpoint.Type)
		}
	}

	// Filter out external domains from captured requests
	ni.requestsMu.Lock()
	filteredRequests := make([]NetworkRequest, 0)
	for _, req := range ni.requests {
		if IsSameDomainOrSubdomain(req.URL, targetURL) {
			filteredRequests = append(filteredRequests, req)
		}
	}
	ni.requests = filteredRequests
	ni.requestsMu.Unlock()

	// Return all captured requests
	return ni.requests, nil
}

// loadAllAssets loads all assets referenced in HTML
func (ni *NetworkInterceptor) loadAllAssets(ctx context.Context, baseURL string, html string) {
	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return
	}

	// Extract all asset URLs
	assetURLs := make(map[string]string) // URL -> Type

	// Script tags
	scriptRegex := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	matches := scriptRegex.FindAllStringSubmatch(html, -1)
	for _, match := range matches {
		if len(match) > 1 {
			assetURL := match[1]
			absoluteURL, err := parsedBase.Parse(assetURL)
			if err == nil {
				assetURLs[absoluteURL.String()] = "js"
			}
		}
	}

	// Link tags (CSS)
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
						assetURLs[absoluteURL.String()] = "css"
					}
				}
			}
		}
	}

	// Image tags
	imgRegex := regexp.MustCompile(`<img[^>]+src=["']([^"']+)["']`)
	matches = imgRegex.FindAllStringSubmatch(html, -1)
	for _, match := range matches {
		if len(match) > 1 {
			assetURL := match[1]
			absoluteURL, err := parsedBase.Parse(assetURL)
			if err == nil {
				assetURLs[absoluteURL.String()] = "image"
			}
		}
	}

	// Load all assets (only same-domain assets)
	for assetURL, assetType := range assetURLs {
		// Only load assets from the same domain
		if IsSameDomainOrSubdomain(assetURL, baseURL) {
			ni.loadAsset(ctx, assetURL, assetType)
		}
	}
}

// loadAsset loads a single asset
func (ni *NetworkInterceptor) loadAsset(ctx context.Context, assetURL, assetType string) {
	// Use a shorter timeout for assets
	originalTimeout := ni.client.Timeout
	ni.client.Timeout = 5 * time.Second
	defer func() { ni.client.Timeout = originalTimeout }()

	resp, err := ni.makeRequestAndCapture(ctx, "GET", assetURL)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Read body if it's JavaScript (to extract API calls)
	if assetType == "js" {
		// Get the body from the captured request
		var body string
		ni.requestsMu.Lock()
		if len(ni.requests) > 0 {
			// Get the last request (this asset)
			lastReq := ni.requests[len(ni.requests)-1]
			body = string(lastReq.Body)
		}
		ni.requestsMu.Unlock()

		// If we don't have the body, read it from response
		if body == "" {
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024)) // 5MB limit
			body = string(bodyBytes)
		}
		
		// Extract API endpoints from this JS file
		apiEndpoints := ni.extractAPIEndpointsFromJSContent(ctx, body, assetURL)
		for _, endpoint := range apiEndpoints {
			// Only add if it's from the same domain
			if IsSameDomainOrSubdomain(endpoint.URL, assetURL) {
				ni.addRequestIfNew(endpoint.URL, endpoint.Method, endpoint.Type)
			}
		}
	}
}

// APIEndpoint represents an API endpoint found in JavaScript
type APIEndpoint struct {
	URL    string
	Method string
	Type   string
}

// extractAPIEndpointsFromJS extracts API endpoints from HTML by finding and parsing JS files
func (ni *NetworkInterceptor) extractAPIEndpointsFromJS(ctx context.Context, html, baseURL string) []APIEndpoint {
	var endpoints []APIEndpoint

	// Find all script tags with src - these should already be loaded by loadAllAssets
	// So we'll extract from the captured requests instead
	ni.requestsMu.Lock()
	for _, req := range ni.requests {
		if req.Type == "js" {
			// Extract API endpoints from this JS file's body
			jsEndpoints := ni.extractAPIEndpointsFromJSContent(ctx, string(req.Body), req.URL)
			endpoints = append(endpoints, jsEndpoints...)
		}
	}
	ni.requestsMu.Unlock()

	// Also check inline scripts in HTML
	inlineScriptRegex := regexp.MustCompile(`<script[^>]*>([\s\S]*?)</script>`)
	inlineMatches := inlineScriptRegex.FindAllStringSubmatch(html, -1)
	for _, match := range inlineMatches {
		if len(match) > 1 {
			jsContent := match[1]
			jsEndpoints := ni.extractAPIEndpointsFromJSContent(ctx, jsContent, baseURL)
			endpoints = append(endpoints, jsEndpoints...)
		}
	}

	return endpoints
}

// extractAPIEndpointsFromJSContent extracts API endpoints from JavaScript content
func (ni *NetworkInterceptor) extractAPIEndpointsFromJSContent(ctx context.Context, jsContent, baseURL string) []APIEndpoint {
	var endpoints []APIEndpoint
	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return endpoints
	}

	// Pattern 1: fetch('url', {...}) or fetch("url", {...})
	fetchRegex := regexp.MustCompile(`fetch\s*\(\s*["']([^"']+)["']`)
	matches := fetchRegex.FindAllStringSubmatch(jsContent, -1)
	for _, match := range matches {
		if len(match) > 1 {
			apiURL := match[1]
			absoluteURL, err := parsedBase.Parse(apiURL)
			if err == nil {
				// Only include if same domain
				if !IsSameDomainOrSubdomain(absoluteURL.String(), baseURL) {
					continue
				}
				// Try to determine method from context
				method := "GET"
				matchIndex := strings.Index(jsContent, match[0])
				if matchIndex >= 0 {
					context := jsContent[matchIndex:min(matchIndex+200, len(jsContent))]
					if strings.Contains(context, "method:") || strings.Contains(context, "method :") {
						methodRegex := regexp.MustCompile(`method\s*:\s*["']([^"']+)["']`)
						methodMatch := methodRegex.FindStringSubmatch(context)
						if len(methodMatch) > 1 {
							method = strings.ToUpper(methodMatch[1])
						}
					} else if strings.Contains(context, "POST") || strings.Contains(context, "post") {
						method = "POST"
					}
				}
				endpoints = append(endpoints, APIEndpoint{
					URL:    absoluteURL.String(),
					Method: method,
					Type:   "api",
				})
			}
		}
	}

	// Pattern 2: XMLHttpRequest
	xhrRegex := regexp.MustCompile(`\.open\s*\(\s*["']([^"']+)["']\s*,\s*["']([^"']+)["']`)
	matches = xhrRegex.FindAllStringSubmatch(jsContent, -1)
	for _, match := range matches {
		if len(match) > 2 {
			method := strings.ToUpper(match[1])
			apiURL := match[2]
			absoluteURL, err := parsedBase.Parse(apiURL)
			if err == nil {
				// Only include if same domain
				if IsSameDomainOrSubdomain(absoluteURL.String(), baseURL) {
					endpoints = append(endpoints, APIEndpoint{
						URL:    absoluteURL.String(),
						Method: method,
						Type:   "api",
					})
				}
			}
		}
	}

	// Pattern 3: axios.get/post/put/delete('url')
	axiosRegex := regexp.MustCompile(`axios\.(get|post|put|delete|patch)\s*\(\s*["']([^"']+)["']`)
	matches = axiosRegex.FindAllStringSubmatch(jsContent, -1)
	for _, match := range matches {
		if len(match) > 2 {
			method := strings.ToUpper(match[1])
			apiURL := match[2]
			absoluteURL, err := parsedBase.Parse(apiURL)
			if err == nil {
				// Only include if same domain
				if IsSameDomainOrSubdomain(absoluteURL.String(), baseURL) {
					endpoints = append(endpoints, APIEndpoint{
						URL:    absoluteURL.String(),
						Method: method,
						Type:   "api",
					})
				}
			}
		}
	}

	// Pattern 4: $.ajax, $.get, $.post (jQuery)
	jqueryRegex := regexp.MustCompile(`\$\.(ajax|get|post|put|delete)\s*\([^)]*url\s*:\s*["']([^"']+)["']`)
	matches = jqueryRegex.FindAllStringSubmatch(jsContent, -1)
	for _, match := range matches {
		if len(match) > 2 {
			method := "GET"
			if match[1] == "post" {
				method = "POST"
			} else if match[1] == "put" {
				method = "PUT"
			} else if match[1] == "delete" {
				method = "DELETE"
			}
			apiURL := match[2]
			absoluteURL, err := parsedBase.Parse(apiURL)
			if err == nil {
				// Only include if same domain
				if IsSameDomainOrSubdomain(absoluteURL.String(), baseURL) {
					endpoints = append(endpoints, APIEndpoint{
						URL:    absoluteURL.String(),
						Method: method,
						Type:   "api",
					})
				}
			}
		}
	}

	// Pattern 5: Common API path patterns
	apiPathRegex := regexp.MustCompile(`["']([^"']*(?:/api/|/rest/|/v1/|/v2/|/graphql)[^"']*)["']`)
	matches = apiPathRegex.FindAllStringSubmatch(jsContent, -1)
	for _, match := range matches {
		if len(match) > 1 {
			apiURL := match[1]
			// Skip if it's already matched by other patterns
			alreadyFound := false
			for _, ep := range endpoints {
				if ep.URL == apiURL {
					alreadyFound = true
					break
				}
			}
			if !alreadyFound {
				absoluteURL, err := parsedBase.Parse(apiURL)
				if err == nil {
					// Only include if same domain
					if IsSameDomainOrSubdomain(absoluteURL.String(), baseURL) {
						endpoints = append(endpoints, APIEndpoint{
							URL:    absoluteURL.String(),
							Method: "GET", // Default, will be tested with multiple methods
							Type:   "api",
						})
					}
				}
			}
		}
	}

	return endpoints
}

// addRequestIfNew adds a request if it hasn't been seen before and belongs to the same domain
func (ni *NetworkInterceptor) addRequestIfNew(urlStr, method, reqType string) {
	// Only add if it's from the same domain
	if !IsSameDomainOrSubdomain(urlStr, ni.baseURL.String()) {
		return
	}

	ni.requestsMu.Lock()
	defer ni.requestsMu.Unlock()

	// Check if already exists
	for _, req := range ni.requests {
		if req.URL == urlStr && req.Method == method {
			return
		}
	}

	ni.requests = append(ni.requests, NetworkRequest{
		URL:       urlStr,
		Method:    method,
		Timestamp: time.Now(),
		Type:      reqType,
	})
}

// detectRequestType detects the type of request from URL and method
func (ni *NetworkInterceptor) detectRequestType(urlStr, method string) string {
	urlLower := strings.ToLower(urlStr)
	
	if strings.Contains(urlLower, ".js") || strings.Contains(urlLower, "/js/") {
		return "js"
	}
	if strings.Contains(urlLower, ".css") || strings.Contains(urlLower, "/css/") {
		return "css"
	}
	if strings.Contains(urlLower, ".png") || strings.Contains(urlLower, ".jpg") || strings.Contains(urlLower, ".jpeg") ||
		strings.Contains(urlLower, ".gif") || strings.Contains(urlLower, ".svg") || strings.Contains(urlLower, ".webp") ||
		strings.Contains(urlLower, ".ico") {
		return "image"
	}
	if strings.Contains(urlLower, "/api/") || strings.Contains(urlLower, "/rest/") || strings.Contains(urlLower, "/graphql") {
		return "api"
	}
	if method == "POST" || method == "PUT" || method == "DELETE" {
		return "api"
	}
	return "html"
}

// GetRequests returns all captured requests
func (ni *NetworkInterceptor) GetRequests() []NetworkRequest {
	ni.requestsMu.Lock()
	defer ni.requestsMu.Unlock()
	
	// Return a copy
	requests := make([]NetworkRequest, len(ni.requests))
	copy(requests, ni.requests)
	return requests
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

