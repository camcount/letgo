package ddosscanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/letgo/ddos"
)

// Validator validates endpoints against attack method requirements
type Validator struct {
	config ScanConfig
	client *http.Client
}

// NewValidator creates a new validator instance
func NewValidator(config ScanConfig) *Validator {
	client := &http.Client{
		Timeout: config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects for validation
		},
	}

	return &Validator{
		config: config,
		client: client,
	}
}

// ValidateEndpoint validates an endpoint against all selected attack methods
func (v *Validator) ValidateEndpoint(ctx context.Context, endpointURL, method string, discoveredBy string) EndpointResult {
	result := EndpointResult{
		URL:              endpointURL,
		Method:           method,
		IsValid:          make(map[ddos.AttackMode]bool),
		ValidationErrors: make(map[ddos.AttackMode]string),
		DiscoveredBy:     discoveredBy,
		AssetType:        detectAssetType(endpointURL, method),
	}

	// First, perform basic connectivity test
	basicInfo := v.testBasicConnectivity(ctx, endpointURL, method)

	// Check if TLS handshake flood is in the attack methods
	hasTLSHandshakeFlood := false
	for _, attackMode := range v.config.AttackMethods {
		if attackMode == ddos.ModeTLSHandshakeFlood {
			hasTLSHandshakeFlood = true
			break
		}
	}

	// For TLS handshake flood, we still want to test TLS even if HTTP request fails
	// because TLS handshake flood doesn't complete HTTP requests
	if basicInfo.StatusCode == 0 {
		// If we have TLS handshake flood, test TLS support anyway
		if hasTLSHandshakeFlood {
			result.SupportsTLS, result.TLSHandshakeTime = v.testTLSSupportWithTiming(ctx, endpointURL)
			// Continue validation for TLS handshake flood even if HTTP failed
		} else {
			// Endpoint is not reachable for other attack modes
			for _, attackMode := range v.config.AttackMethods {
				result.IsValid[attackMode] = false
				result.ValidationErrors[attackMode] = "Endpoint not reachable"
			}
			return result
		}
	} else {
		result.StatusCode = basicInfo.StatusCode
		result.ResponseTime = basicInfo.ResponseTime
		result.ResponseSize = basicInfo.ResponseSize
		result.Headers = basicInfo.Headers

		// Test HTTP/2 support
		result.SupportsHTTP2 = v.testHTTP2Support(ctx, endpointURL)

		// Test TLS handshake support and measure handshake time
		result.SupportsTLS, result.TLSHandshakeTime = v.testTLSSupportWithTiming(ctx, endpointURL)
	}

	// Test connection keep-alive
	result.KeepsConnection = v.testKeepAlive(ctx, endpointURL, method)
	result.ConnectionTimeout = v.testConnectionTimeout(ctx, endpointURL, method)

	// Test large body acceptance (for RUDY)
	if method == "POST" {
		result.AcceptsLargeBody, result.MaxBodySize = v.testLargeBody(ctx, endpointURL)
	}

	// Validate against each attack method
	for _, attackMode := range v.config.AttackMethods {
		criteria := GetValidationCriteria(attackMode)
		isValid, errorMsg := v.validateAgainstCriteria(ctx, result, criteria, attackMode)
		result.IsValid[attackMode] = isValid
		if !isValid {
			result.ValidationErrors[attackMode] = errorMsg
		}
	}

	// Generate cURL command if valid for at least one method
	if v.hasAnyValid(result) {
		result.CurlCommand = v.generateCurlCommand(result)
	}

	return result
}

// testBasicConnectivity performs a basic connectivity test
func (v *Validator) testBasicConnectivity(ctx context.Context, endpointURL, method string) struct {
	StatusCode   int
	ResponseTime time.Duration
	ResponseSize int64
	Headers      http.Header
} {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, method, endpointURL, nil)
	if err != nil {
		return struct {
			StatusCode   int
			ResponseTime time.Duration
			ResponseSize int64
			Headers      http.Header
		}{}
	}

	// Set headers
	req.Header.Set("User-Agent", v.config.UserAgent)
	if v.config.CustomHeaders != nil {
		for k, v := range v.config.CustomHeaders {
			req.Header.Set(k, v)
		}
	}

	resp, err := v.client.Do(req)
	responseTime := time.Since(start)
	if err != nil {
		return struct {
			StatusCode   int
			ResponseTime time.Duration
			ResponseSize int64
			Headers      http.Header
		}{}
	}
	defer resp.Body.Close()

	// Read response body (limit size)
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit

	return struct {
		StatusCode   int
		ResponseTime time.Duration
		ResponseSize int64
		Headers      http.Header
	}{
		StatusCode:   resp.StatusCode,
		ResponseTime: responseTime,
		ResponseSize: int64(len(bodyBytes)),
		Headers:      resp.Header,
	}
}

// testHTTP2Support tests if endpoint supports HTTP/2
func (v *Validator) testHTTP2Support(ctx context.Context, endpointURL string) bool {
	parsed, err := url.Parse(endpointURL)
	if err != nil {
		return false
	}

	// HTTP/2 requires HTTPS
	if parsed.Scheme != "https" {
		return false
	}

	// Try to make a request and check if HTTP/2 is used
	req, err := http.NewRequestWithContext(ctx, "GET", endpointURL, nil)
	if err != nil {
		return false
	}

	req.Header.Set("User-Agent", v.config.UserAgent)

	// Create transport with HTTP/2 support
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Check if HTTP/2 was actually used
	return resp.ProtoMajor == 2
}

// testTLSSupportWithTiming tests if endpoint supports TLS handshake and measures handshake time
func (v *Validator) testTLSSupportWithTiming(ctx context.Context, endpointURL string) (bool, time.Duration) {
	parsed, err := url.Parse(endpointURL)
	if err != nil {
		return false, 0
	}

	// TLS requires HTTPS
	if parsed.Scheme != "https" {
		return false, 0
	}

	// Extract host and port
	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "443" // Default HTTPS port
	}

	// Test TLS handshake by attempting to establish a TLS connection
	// This mimics what the TLS handshake flood attack does
	return v.performTLSHandshakeTestWithTiming(ctx, host, port)
}

// testTLSSupport tests if endpoint supports TLS handshake (backward compatibility)
func (v *Validator) testTLSSupport(ctx context.Context, endpointURL string) bool {
	supports, _ := v.testTLSSupportWithTiming(ctx, endpointURL)
	return supports
}

// performTLSHandshakeTestWithTiming performs a TLS handshake test and measures the time taken
func (v *Validator) performTLSHandshakeTestWithTiming(ctx context.Context, host, port string) (bool, time.Duration) {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	// Create TLS config
	tlsConfig := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: false, // Verify certificate
	}

	// Measure handshake time
	start := time.Now()
	conn, err := tls.DialWithDialer(dialer, "tcp", host+":"+port, tlsConfig)
	handshakeTime := time.Since(start)

	if err != nil {
		return false, 0
	}
	defer conn.Close()

	// If handshake succeeds, endpoint supports TLS
	return true, handshakeTime
}

// performTLSHandshakeTest performs a TLS handshake test without completing HTTP request (backward compatibility)
func (v *Validator) performTLSHandshakeTest(ctx context.Context, host, port string) bool {
	supports, _ := v.performTLSHandshakeTestWithTiming(ctx, host, port)
	return supports
}

// testKeepAlive tests if connection supports keep-alive
func (v *Validator) testKeepAlive(ctx context.Context, endpointURL, method string) bool {
	req, err := http.NewRequestWithContext(ctx, method, endpointURL, nil)
	if err != nil {
		return false
	}

	req.Header.Set("User-Agent", v.config.UserAgent)
	req.Header.Set("Connection", "keep-alive")

	resp, err := v.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Check Connection header
	connHeader := resp.Header.Get("Connection")
	return strings.ToLower(connHeader) == "keep-alive" || resp.Header.Get("Keep-Alive") != ""
}

// testConnectionTimeout tests how long a connection can stay open
func (v *Validator) testConnectionTimeout(ctx context.Context, endpointURL, method string) time.Duration {
	// Create a request with a long timeout
	req, err := http.NewRequestWithContext(ctx, method, endpointURL, nil)
	if err != nil {
		return 0
	}

	req.Header.Set("User-Agent", v.config.UserAgent)
	req.Header.Set("Connection", "keep-alive")

	// Use a client with longer timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return time.Since(start)
	}
	defer resp.Body.Close()

	// Try to keep connection open by reading slowly
	done := make(chan bool)
	go func() {
		io.Copy(io.Discard, resp.Body)
		done <- true
	}()

	select {
	case <-done:
		return time.Since(start)
	case <-time.After(30 * time.Second):
		return 30 * time.Second
	}
}

// testLargeBody tests if endpoint accepts large POST bodies
func (v *Validator) testLargeBody(ctx context.Context, endpointURL string) (bool, int64) {
	// Test with 1MB body
	testSize := int64(1024 * 1024) // 1MB
	body := strings.Repeat("A", int(testSize))

	req, err := http.NewRequestWithContext(ctx, "POST", endpointURL, strings.NewReader(body))
	if err != nil {
		return false, 0
	}

	req.Header.Set("User-Agent", v.config.UserAgent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ContentLength = testSize

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, 0
	}
	defer resp.Body.Close()

	// If we get 413 (Request Entity Too Large), it means server accepts large bodies but this one is too big
	// If we get 200-299 or 400, it might accept the body
	if resp.StatusCode == 413 {
		// Server accepts large bodies but this one is too big
		// Try smaller sizes
		return v.findMaxBodySize(ctx, endpointURL)
	}

	// If status is 200-299 or 400, it likely accepted the body
	if resp.StatusCode >= 200 && resp.StatusCode < 500 {
		// Try to find maximum size
		return v.findMaxBodySize(ctx, endpointURL)
	}

	return false, 0
}

// findMaxBodySize finds the maximum body size accepted
func (v *Validator) findMaxBodySize(ctx context.Context, endpointURL string) (bool, int64) {
	sizes := []int64{
		1024,             // 1KB
		10 * 1024,        // 10KB
		100 * 1024,       // 100KB
		1024 * 1024,      // 1MB
		5 * 1024 * 1024,  // 5MB
		10 * 1024 * 1024, // 10MB
	}

	for _, size := range sizes {
		body := strings.Repeat("A", int(size))
		req, err := http.NewRequestWithContext(ctx, "POST", endpointURL, strings.NewReader(body))
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", v.config.UserAgent)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.ContentLength = size

		client := &http.Client{
			Timeout: 5 * time.Second,
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 413 {
			// This size is too large, return previous size
			return true, size / 2
		}

		if resp.StatusCode >= 200 && resp.StatusCode < 500 {
			// This size works
			continue
		}
	}

	return true, 10 * 1024 * 1024 // Default to 10MB if all sizes work
}

// validateAgainstCriteria validates endpoint against specific attack method criteria
func (v *Validator) validateAgainstCriteria(ctx context.Context, result EndpointResult, criteria ValidationCriteria, attackMode ddos.AttackMode) (bool, string) {
	// Check status code (skip if no status codes are required, e.g., for TLS handshake flood)
	if len(criteria.RequiredStatusCodes) > 0 {
		statusValid := false
		for _, code := range criteria.RequiredStatusCodes {
			if result.StatusCode == code {
				statusValid = true
				break
			}
		}
		if !statusValid {
			return false, fmt.Sprintf("Status code %d not in required codes %v", result.StatusCode, criteria.RequiredStatusCodes)
		}
	}

	// Check HTTPS requirement
	if criteria.RequiresHTTPS {
		parsed, err := url.Parse(result.URL)
		if err != nil || parsed.Scheme != "https" {
			return false, "HTTPS required but URL is not HTTPS"
		}
	}

	// Check TLS requirement
	if criteria.RequiresTLS {
		if !result.SupportsTLS {
			return false, "TLS handshake support required but not available"
		}
	}

	// Check HTTP/2 requirement
	if criteria.RequiresHTTP2 {
		if !result.SupportsHTTP2 {
			return false, "HTTP/2 support required but not available"
		}
	}

	// Check POST requirement
	if criteria.RequiresPOST {
		if result.Method != "POST" {
			return false, "POST method required"
		}
	}

	// Check response time (more lenient for assets)
	maxAllowedTime := criteria.MaxResponseTime
	if result.AssetType != "" && result.AssetType != "html" && result.AssetType != "api" {
		// Assets can be slower (up to 2 seconds) since they're often cached and good for flood attacks
		maxAllowedTime = criteria.MaxResponseTime * 2
		if maxAllowedTime < 2*time.Second {
			maxAllowedTime = 2 * time.Second
		}
	}
	if criteria.MaxResponseTime > 0 && result.ResponseTime > maxAllowedTime {
		return false, fmt.Sprintf("Response time %v exceeds maximum %v", result.ResponseTime, maxAllowedTime)
	}

	// Check connection timeout (for slowloris)
	if criteria.MinConnectionTimeout > 0 {
		if result.ConnectionTimeout < criteria.MinConnectionTimeout {
			return false, fmt.Sprintf("Connection timeout %v is less than required %v", result.ConnectionTimeout, criteria.MinConnectionTimeout)
		}
	}

	// Check keep-alive requirement
	if criteria.RequiresKeepAlive {
		if !result.KeepsConnection {
			return false, "Keep-alive connection required but not supported"
		}
	}

	// Check body size (for RUDY)
	if criteria.RequiresPOST && criteria.MinBodySize > 0 {
		if !result.AcceptsLargeBody || result.MaxBodySize < criteria.MinBodySize {
			return false, fmt.Sprintf("Large body support required (min %d bytes) but endpoint only accepts up to %d bytes", criteria.MinBodySize, result.MaxBodySize)
		}
	}

	// Check concurrency (for flood)
	if criteria.RequiresConcurrency {
		// Test with concurrent requests
		if !v.testConcurrency(ctx, result.URL, result.Method) {
			return false, "Endpoint does not handle concurrent requests well"
		}
	}

	// Check TLS handshake time (for TLS handshake flood optimization)
	if criteria.MaxTLSHandshakeTime > 0 && attackMode == ddos.ModeTLSHandshakeFlood {
		if result.TLSHandshakeTime == 0 || result.TLSHandshakeTime > criteria.MaxTLSHandshakeTime {
			return false, fmt.Sprintf("TLS handshake time %v exceeds maximum %v", result.TLSHandshakeTime, criteria.MaxTLSHandshakeTime)
		}
	}

	// Check concurrent TLS handshakes (for TLS handshake flood)
	if criteria.MinConcurrentTLSHandshakes > 0 && attackMode == ddos.ModeTLSHandshakeFlood {
		if !v.testConcurrentTLSHandshakes(ctx, result.URL, criteria.MinConcurrentTLSHandshakes) {
			return false, fmt.Sprintf("Endpoint does not handle at least %d concurrent TLS handshakes", criteria.MinConcurrentTLSHandshakes)
		}
	}

	return true, ""
}

// testConcurrency tests if endpoint handles concurrent requests
func (v *Validator) testConcurrency(ctx context.Context, endpointURL, method string) bool {
	const numRequests = 10
	var wg sync.WaitGroup
	successCount := 0
	var mu sync.Mutex

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequestWithContext(ctx, method, endpointURL, nil)
			if err != nil {
				return
			}

			req.Header.Set("User-Agent", v.config.UserAgent)

			client := &http.Client{
				Timeout: 5 * time.Second,
			}

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode >= 200 && resp.StatusCode < 400 {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// At least 70% should succeed
	return successCount >= (numRequests * 70 / 100)
}

// testConcurrentTLSHandshakes tests if endpoint can handle multiple concurrent TLS handshakes
func (v *Validator) testConcurrentTLSHandshakes(ctx context.Context, endpointURL string, minSuccess int) bool {
	parsed, err := url.Parse(endpointURL)
	if err != nil {
		return false
	}

	host := parsed.Hostname()
	port := parsed.Port()
	if port == "" {
		port = "443"
	}

	const numHandshakes = 10
	var wg sync.WaitGroup
	successCount := 0
	var mu sync.Mutex

	for i := 0; i < numHandshakes; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			supports, _ := v.performTLSHandshakeTestWithTiming(ctx, host, port)
			if supports {
				mu.Lock()
				successCount++
				mu.Unlock()
			}
		}()
	}

	wg.Wait()

	// Must have at least minSuccess successful handshakes
	return successCount >= minSuccess
}

// hasAnyValid checks if endpoint is valid for any attack method
func (v *Validator) hasAnyValid(result EndpointResult) bool {
	for _, valid := range result.IsValid {
		if valid {
			return true
		}
	}
	return false
}

// generateCurlCommand generates a cURL command from endpoint result
func (v *Validator) generateCurlCommand(result EndpointResult) string {
	var parts []string
	parts = append(parts, "curl")

	// Add method
	if result.Method != "GET" {
		parts = append(parts, "-X", result.Method)
	}

	// Add URL
	parts = append(parts, fmt.Sprintf("'%s'", result.URL))

	// Add headers
	if result.Headers != nil {
		for key, values := range result.Headers {
			if len(values) > 0 {
				// Only add important headers
				importantHeaders := []string{"Content-Type", "Authorization", "User-Agent", "Accept"}
				for _, important := range importantHeaders {
					if strings.EqualFold(key, important) {
						parts = append(parts, "-H", fmt.Sprintf("'%s: %s'", key, values[0]))
						break
					}
				}
			}
		}
	}

	// Add User-Agent if not in headers
	hasUserAgent := false
	if result.Headers != nil {
		for key := range result.Headers {
			if strings.EqualFold(key, "User-Agent") {
				hasUserAgent = true
				break
			}
		}
	}
	if !hasUserAgent {
		parts = append(parts, "-H", fmt.Sprintf("'User-Agent: %s'", v.config.UserAgent))
	}

	// Add data for POST requests
	if result.Method == "POST" && result.AcceptsLargeBody {
		// Add a placeholder for data
		parts = append(parts, "-d", "'data=test'")
	}

	return strings.Join(parts, " \\\n  ")
}

// detectAssetType detects the type of asset from URL and method
func detectAssetType(endpointURL, method string) string {
	urlLower := strings.ToLower(endpointURL)

	// Check file extensions
	if strings.Contains(urlLower, ".js") || strings.Contains(urlLower, "/js/") || strings.Contains(urlLower, "/javascript/") {
		return "js"
	}
	if strings.Contains(urlLower, ".css") || strings.Contains(urlLower, "/css/") || strings.Contains(urlLower, "/styles/") {
		return "css"
	}
	if strings.Contains(urlLower, ".png") || strings.Contains(urlLower, ".jpg") || strings.Contains(urlLower, ".jpeg") ||
		strings.Contains(urlLower, ".gif") || strings.Contains(urlLower, ".svg") || strings.Contains(urlLower, ".webp") ||
		strings.Contains(urlLower, ".ico") || strings.Contains(urlLower, "/img/") || strings.Contains(urlLower, "/images/") {
		return "image"
	}
	if strings.Contains(urlLower, ".woff") || strings.Contains(urlLower, ".woff2") || strings.Contains(urlLower, ".ttf") ||
		strings.Contains(urlLower, ".otf") || strings.Contains(urlLower, "/fonts/") {
		return "font"
	}
	if strings.Contains(urlLower, "/api/") {
		return "api"
	}
	if strings.Contains(urlLower, ".json") {
		return "json"
	}
	if strings.Contains(urlLower, ".xml") {
		return "xml"
	}
	if strings.Contains(urlLower, "/static/") || strings.Contains(urlLower, "/assets/") || strings.Contains(urlLower, "/public/") {
		return "static"
	}

	return "html"
}
