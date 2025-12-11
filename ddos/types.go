package ddos

import (
	"context"
	"sync"
	"time"
)

// AttackMode represents the type of DDoS attack
type AttackMode string

const (
	// ModeFlood sends maximum concurrent HTTP requests
	ModeFlood AttackMode = "flood"
	// ModeSlowloris holds connections open with partial headers
	ModeSlowloris AttackMode = "slowloris"
	// ModeMixed combines flood and slowloris approaches
	ModeMixed AttackMode = "mixed"
	// ModeHTTP2StreamFlood floods server with HTTP/2 streams
	ModeHTTP2StreamFlood AttackMode = "http2-stream-flood"
	// ModeRUDY sends slow HTTP POST requests (R-U-Dead-Yet)
	ModeRUDY AttackMode = "rudy"
)

// DDoSConfig holds configuration for DDoS attack
type DDoSConfig struct {
	TargetURL        string
	Method           string
	Headers          map[string]string
	Body             string
	ContentType      string
	MaxThreads       int
	Duration         time.Duration
	Timeout          time.Duration
	AttackMode       AttackMode
	RateLimit        int // Requests per second (0 = unlimited)
	FollowRedirects  bool
	ReuseConnections bool

	// Slowloris specific
	SlowlorisDelay time.Duration // Delay between partial header sends

	// Proxy settings
	UseProxy    bool     // Whether to use proxies
	ProxyList   []string // List of proxy URLs (e.g., "http://1.2.3.4:8080")
	RotateProxy bool     // Rotate through proxies for each request

	// User Agent settings
	UseCustomUserAgents bool   // Whether to use custom user agents from file
	UserAgentFilePath   string // Path to file containing custom user agents (one per line)

	// TLS Attack settings
	UseTLSAttack      bool     // Enable TLS attack combinations
	ForceTLS          bool     // Force TLS even on HTTP URLs
	TLSHandshakeFlood bool     // Initiate many TLS handshakes without completing HTTP requests
	TLSRenegotiation  bool     // Force TLS renegotiation on connections
	TLSMinVersion     uint16   // Minimum TLS version (e.g., tls.VersionTLS10, 0 = default)
	TLSMaxVersion     uint16   // Maximum TLS version (e.g., tls.VersionTLS13, 0 = default)
	TLSCipherSuites   []uint16 // Specific cipher suites to use (optional, nil = default)

	// HTTP/2 and Advanced settings
	UseHTTP2          bool          // Enable HTTP/2 support
	UsePipelining     bool          // Enable HTTP pipelining
	AdaptiveRateLimit bool          // Enable adaptive rate limiting
	MaxStreamsPerConn int           // Maximum HTTP/2 streams per connection (default: 100)
	RUDYDelay         time.Duration // Delay between bytes in RUDY attack
	RUDYBodySize      int           // Size of POST body for RUDY attack (in bytes)

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
	proxyIndex        int64 // Current proxy index for rotation

	// User agents
	userAgents     []string // List of user agents to rotate from
	userAgentIndex int64

	startTime time.Time
	running   bool
	mu        sync.Mutex
}

