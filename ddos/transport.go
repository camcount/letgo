package ddos

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
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

