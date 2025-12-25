package ddos

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// FormatBytes formats bytes to human-readable string
func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// FormatDuration formats duration to human-readable string
func FormatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
}

// GoroutineLimiter limits the number of concurrent goroutines
type GoroutineLimiter struct {
	semaphore chan struct{}
	wg        sync.WaitGroup
	blocking  bool // If true, blocks when full; if false, skips execution
}

// NewGoroutineLimiter creates a new limiter with max concurrent goroutines
// Defaults to blocking mode for stability
func NewGoroutineLimiter(maxConcurrent int) *GoroutineLimiter {
	if maxConcurrent <= 0 {
		maxConcurrent = 1000 // Default limit
	}
	return &GoroutineLimiter{
		semaphore: make(chan struct{}, maxConcurrent),
		blocking:  true, // Default to blocking for stability
	}
}

// NewGoroutineLimiterNonBlocking creates a new limiter with non-blocking behavior
// Use this only when you need non-blocking behavior (e.g., for specific use cases)
func NewGoroutineLimiterNonBlocking(maxConcurrent int) *GoroutineLimiter {
	if maxConcurrent <= 0 {
		maxConcurrent = 1000 // Default limit
	}
	return &GoroutineLimiter{
		semaphore: make(chan struct{}, maxConcurrent),
		blocking:  false, // Non-blocking mode
	}
}

// Execute runs a function with goroutine limiting and panic recovery
// Uses blocking mode by default for stability, but can be configured for non-blocking
func (gl *GoroutineLimiter) Execute(fn func()) {
	if gl == nil || gl.semaphore == nil {
		// Limiter is closed or invalid, skip execution
		return
	}

	if gl.blocking {
		// Blocking mode: wait for semaphore slot (stable, prevents request loss)
		gl.semaphore <- struct{}{} // Acquire (blocks if full)
		gl.wg.Add(1)
		go func() {
			defer func() {
				<-gl.semaphore // Release
				gl.wg.Done()
				// Recover from panics to prevent crashes
				if r := recover(); r != nil {
					// Log or handle panic if needed
					_ = r
				}
			}()
			fn()
		}()
	} else {
		// Non-blocking mode: skip if semaphore is full (for specific use cases)
		select {
		case gl.semaphore <- struct{}{}: // Acquire
			gl.wg.Add(1)
			go func() {
				defer func() {
					<-gl.semaphore // Release
					gl.wg.Done()
					// Recover from panics to prevent crashes
					if r := recover(); r != nil {
						// Log or handle panic if needed
						_ = r
					}
				}()
				fn()
			}()
		default:
			// Semaphore full - skip this execution (non-blocking)
			return
		}
	}
}

// Wait waits for all goroutines to complete
func (gl *GoroutineLimiter) Wait() {
	gl.wg.Wait()
}

// Close closes the limiter (waits for all goroutines first)
func (gl *GoroutineLimiter) Close() {
	if gl == nil {
		return
	}
	// Wait for all goroutines to complete
	gl.Wait()
	// Don't close the semaphore channel - it may still be in use
	// Instead, just mark it as closed by setting it to nil or leaving it open
	// Closing a channel that goroutines are trying to send to causes panic
}

// TokenBucket implements a token bucket rate limiter
type TokenBucket struct {
	capacity    int64      // Maximum tokens in bucket
	tokens      int64      // Current tokens (atomic)
	refillRate  int64      // Tokens per second
	lastRefill  int64      // Last refill time in nanoseconds (atomic)
	refillMutex sync.Mutex // Protects refill operation
}

// NewTokenBucket creates a new token bucket rate limiter
func NewTokenBucket(ratePerSecond int) *TokenBucket {
	if ratePerSecond <= 0 {
		return nil // No rate limiting
	}
	// Capacity is 2x the rate for smooth operation
	capacity := int64(ratePerSecond * 2)
	if capacity < 100 {
		capacity = 100 // Minimum capacity
	}
	return &TokenBucket{
		capacity:   capacity,
		tokens:     capacity, // Start with full bucket
		refillRate: int64(ratePerSecond),
		lastRefill: time.Now().UnixNano(),
	}
}

// Allow checks if a request is allowed and consumes a token
func (tb *TokenBucket) Allow() bool {
	if tb == nil {
		return true // No rate limiting
	}

	now := time.Now().UnixNano()
	tb.refillMutex.Lock()
	defer tb.refillMutex.Unlock()

	// Refill tokens based on elapsed time
	elapsed := now - atomic.LoadInt64(&tb.lastRefill)
	if elapsed > 0 {
		tokensToAdd := (elapsed * tb.refillRate) / 1e9 // Convert nanoseconds to seconds
		currentTokens := atomic.LoadInt64(&tb.tokens)
		newTokens := currentTokens + tokensToAdd
		if newTokens > tb.capacity {
			newTokens = tb.capacity
		}
		atomic.StoreInt64(&tb.tokens, newTokens)
		atomic.StoreInt64(&tb.lastRefill, now)
	}

	// Check if we have tokens available
	currentTokens := atomic.LoadInt64(&tb.tokens)
	if currentTokens > 0 {
		atomic.AddInt64(&tb.tokens, -1)
		return true
	}

	return false // No tokens available
}

// isHTTP2Error detects if an error is HTTP/2 specific
// This helps identify connection state issues like "Unsolicited response" errors
func isHTTP2Error(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	// Check for common HTTP/2 error patterns
	return strings.Contains(errStr, "Unsolicited response") ||
		strings.Contains(errStr, "http2:") ||
		strings.Contains(errStr, "stream") ||
		strings.Contains(errStr, "idle HTTP channel")
}

// isConnectionHealthy performs a lightweight health check on an HTTP client
// This helps prevent using dead or stale connections
func isConnectionHealthy(client *http.Client) bool {
	if client == nil {
		return false
	}

	// Check if transport is valid
	if transport, ok := client.Transport.(*http.Transport); ok {
		if transport == nil {
			return false
		}
		// Transport exists and is not explicitly disabled
		// Note: We can't easily check connection state without making a request,
		// so we rely on error handling at request time for actual health validation
		return true
	}

	return true // Assume healthy if we can't determine
}

// RetryWithBackoff executes a function with exponential backoff retry logic
// This helps recover from transient connection errors
func RetryWithBackoff(maxRetries int, baseDelay time.Duration, fn func() error) error {
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		err := fn()
		if err == nil {
			return nil // Success
		}
		lastErr = err

		// Don't retry on last attempt
		if attempt < maxRetries-1 {
			// Exponential backoff: baseDelay * 2^attempt
			delay := baseDelay * time.Duration(1<<uint(attempt))
			if delay > 5*time.Second {
				delay = 5 * time.Second // Cap at 5 seconds
			}
			time.Sleep(delay)
		}
	}
	return lastErr
}

// ClassifyError categorizes errors for better error handling
type ErrorType int

const (
	ErrorTypeUnknown ErrorType = iota
	ErrorTypeHTTP2
	ErrorTypeConnection
	ErrorTypeTimeout
	ErrorTypeProxy
)

// ClassifyError categorizes an error to help with appropriate handling
func ClassifyError(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}

	errStr := err.Error()

	// HTTP/2 errors
	if isHTTP2Error(err) {
		return ErrorTypeHTTP2
	}

	// Connection errors
	if strings.Contains(errStr, "connection") ||
		strings.Contains(errStr, "refused") ||
		strings.Contains(errStr, "reset") {
		return ErrorTypeConnection
	}

	// Timeout errors
	if strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "deadline") {
		return ErrorTypeTimeout
	}

	// Proxy errors
	if strings.Contains(errStr, "proxy") {
		return ErrorTypeProxy
	}

	return ErrorTypeUnknown
}
