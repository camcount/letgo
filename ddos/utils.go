package ddos

import (
	"fmt"
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
}

// NewGoroutineLimiter creates a new limiter with max concurrent goroutines
func NewGoroutineLimiter(maxConcurrent int) *GoroutineLimiter {
	if maxConcurrent <= 0 {
		maxConcurrent = 1000 // Default limit
	}
	return &GoroutineLimiter{
		semaphore: make(chan struct{}, maxConcurrent),
	}
}

// Execute runs a function with goroutine limiting and panic recovery
// Optimized: non-blocking with select default (removed timeout for maximum throughput)
func (gl *GoroutineLimiter) Execute(fn func()) {
	if gl == nil || gl.semaphore == nil {
		// Limiter is closed or invalid, skip execution
		return
	}

	// Non-blocking semaphore acquisition - use select with default
	// This prevents blocking and allows maximum throughput
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
		// This allows maximum throughput without blocking workers
		return
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
