package pathtraversal

import (
	"sync"
	"sync/atomic"
	"time"
)

// PathTraversalConfig holds configuration for path traversal testing
type PathTraversalConfig struct {
	TargetURL        string        // Target URL to test
	MaxThreads       int           // Number of concurrent workers (default: 10)
	Timeout          time.Duration // HTTP request timeout (default: 10s)
	FollowRedirects  bool          // Follow HTTP redirects (default: false)
	UseProxy         bool          // Use proxy for requests (default: false)
	ProxyList        []string      // List of proxies to rotate through
	RotateProxy      bool          // Rotate proxies between requests (default: false)
	TestParameters   []string      // Custom parameters to test (auto-discovered if empty)
	SkipBaselineTest bool          // Skip baseline response test (default: false)
	OnProgress       func(Stats)   // Callback function for progress updates
}

// PathTraversalResult represents a single test result
type PathTraversalResult struct {
	URL          string        // Full URL tested
	Parameter    string        // Parameter name that was tested
	Payload      string        // Payload that was used
	StatusCode   int           // HTTP response status code
	ResponseSize int           // Size of response body in bytes
	Indicator    string        // Detection indicator (e.g., "content_match", "size_variance", "status_anomaly")
	Confidence   float64       // Confidence score 0-100
	Evidence     string        // Response snippet or evidence
	IsVulnerable bool          // Whether parameter is considered vulnerable
	ResponseTime time.Duration // Time taken for request
	EncodingType string        // Encoding used for payload (plain, url_encoded, double_encoded, etc.)
}

// Stats holds real-time statistics about the attack
type Stats struct {
	PayloadsTested       int64
	VulnerabilitiesFound int64
	ParametersScanned    int
	ParametersVulnerable int
	TotalParameters      int
	TotalPayloads        int
	AvgResponseTime      time.Duration
	ElapsedTime          time.Duration
	StartTime            time.Time
	LastUpdate           time.Time
}

// PathTraversal represents the main path traversal attack engine
type PathTraversal struct {
	config            PathTraversalConfig
	results           []PathTraversalResult
	resultsMu         sync.RWMutex
	stats             Stats
	statsMu           sync.RWMutex
	discoveredParams  []string
	paramsMu          sync.RWMutex
	wg                sync.WaitGroup
	activeTasks       int64
	stopChan          chan struct{}
	startTime         time.Time
	totalResponseTime int64 // nanoseconds
	payloadsTested    atomic.Int64
	vulnFound         atomic.Int64
}

// New creates a new PathTraversal instance with default values
func New(config PathTraversalConfig) *PathTraversal {
	if config.MaxThreads <= 0 {
		config.MaxThreads = 10
	}
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}
	// Default to skipping baseline test for faster scanning
	if !config.SkipBaselineTest {
		config.SkipBaselineTest = true
	}

	return &PathTraversal{
		config:           config,
		results:          make([]PathTraversalResult, 0),
		discoveredParams: make([]string, 0),
		stopChan:         make(chan struct{}),
		startTime:        time.Now(),
	}
}
