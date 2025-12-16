package ddosscanner

import (
	"net/http"
	"time"

	"github.com/letgo/ddos"
	"github.com/letgo/scanner"
)

// ScanConfig holds configuration for target scanning
type ScanConfig struct {
	TargetURL        string
	AttackMethods    []ddos.AttackMode
	MaxThreads       int
	Timeout          time.Duration
	MaxDepth         int // Maximum crawl depth
	MaxPages         int // Maximum pages to crawl
	UserAgent        string
	CustomHeaders    map[string]string
	OnProgress       ProgressCallback
	MaxValidPerMethod map[ddos.AttackMode]int // Optional cap on how many valid endpoints to keep per attack method (0 = no limit)
}

// ProgressCallback is called with progress updates
type ProgressCallback func(phase string, current, total int, percentage float64)

// EndpointResult represents a discovered endpoint with validation results
type EndpointResult struct {
	URL               string
	Method            string
	StatusCode        int
	ResponseTime      time.Duration
	ResponseSize      int64
	Headers           http.Header
	SupportsHTTP2     bool
	KeepsConnection   bool
	AcceptsLargeBody  bool
	MaxBodySize       int64
	ConnectionTimeout time.Duration
	SupportsTLS       bool                       // Whether endpoint supports TLS handshake
	TLSHandshakeTime  time.Duration              // Time taken for TLS handshake (for TLS flood optimization)
	IsValid           map[ddos.AttackMode]bool   // Validation result for each attack method
	ValidationErrors  map[ddos.AttackMode]string // Error messages for failed validations
	CurlCommand       string                     // Generated cURL command
	DiscoveredBy      string                     // How it was discovered: "scanner", "crawler", "common", "asset"
	AssetType         string                     // Type of asset: "js", "css", "image", "font", "api", "html", etc.
}

// ScanResult holds all scan results
type ScanResult struct {
	TargetURL       string
	ScanStartTime   time.Time
	ScanEndTime     time.Time
	Endpoints       []EndpointResult
	ValidEndpoints  map[ddos.AttackMode][]EndpointResult // Grouped by attack method
	TotalDiscovered int
	TotalValidated  int
}

// ValidationCriteria defines requirements for each attack method
type ValidationCriteria struct {
	MinResponseTime            time.Duration
	MaxResponseTime            time.Duration
	RequiredStatusCodes        []int
	RequiresHTTPS              bool
	RequiresHTTP2              bool
	RequiresPOST               bool
	MinBodySize                int64
	MaxBodySize                int64
	MinConnectionTimeout       time.Duration
	RequiresKeepAlive          bool
	RequiresConcurrency        bool
	RequiresTLS                bool          // Whether TLS handshake capability is required
	MaxTLSHandshakeTime        time.Duration // Maximum allowed TLS handshake time (for optimization)
	MinConcurrentTLSHandshakes int           // Minimum successful concurrent TLS handshakes required
}

// GetValidationCriteria returns criteria for a specific attack method
func GetValidationCriteria(mode ddos.AttackMode) ValidationCriteria {
	switch mode {
	case ddos.ModeFlood:
		return ValidationCriteria{
			MinResponseTime:     0,
			MaxResponseTime:     1000 * time.Millisecond,        // More lenient for assets (1 second)
			RequiredStatusCodes: []int{200, 201, 202, 204, 304}, // 304 Not Modified is good for cached assets
			RequiresHTTPS:       false,
			RequiresHTTP2:       false,
			RequiresPOST:        false,
			RequiresConcurrency: true,
		}
	case ddos.ModeSlowloris:
		return ValidationCriteria{
			MinResponseTime:      0,
			MaxResponseTime:      30 * time.Second,
			RequiredStatusCodes:  []int{200, 201, 202, 204},
			RequiresHTTPS:        false,
			RequiresHTTP2:        false,
			RequiresPOST:         false,
			MinConnectionTimeout: 10 * time.Second,
			RequiresKeepAlive:    true,
		}
	case ddos.ModeHTTP2StreamFlood:
		return ValidationCriteria{
			MinResponseTime:     0,
			MaxResponseTime:     500 * time.Millisecond,
			RequiredStatusCodes: []int{200, 201, 202, 204},
			RequiresHTTPS:       true,
			RequiresHTTP2:       true,
			RequiresConcurrency: true,
		}
	case ddos.ModeRUDY:
		return ValidationCriteria{
			MinResponseTime:     0,
			MaxResponseTime:     30 * time.Second,
			RequiredStatusCodes: []int{200, 201, 202, 204, 400, 413}, // 413 = Request Entity Too Large (but accepts large body)
			RequiresHTTPS:       false,
			RequiresHTTP2:       false,
			RequiresPOST:        true,
			MinBodySize:         1024 * 1024,      // 1MB minimum
			MaxBodySize:         10 * 1024 * 1024, // 10MB maximum
		}
	case ddos.ModeMixed:
		return ValidationCriteria{
			MinResponseTime:      0,
			MaxResponseTime:      500 * time.Millisecond,
			RequiredStatusCodes:  []int{200, 201, 202, 204},
			RequiresHTTPS:        false,
			RequiresHTTP2:        false,
			RequiresPOST:         false,
			MinConnectionTimeout: 10 * time.Second,
			RequiresKeepAlive:    true,
			RequiresConcurrency:  true,
		}
	case ddos.ModeTLSHandshakeFlood:
		return ValidationCriteria{
			MinResponseTime:            0,
			MaxResponseTime:            0,       // No response time limit for TLS handshake (we don't complete HTTP requests)
			RequiredStatusCodes:        []int{}, // No status code required (we don't complete HTTP requests)
			RequiresHTTPS:              true,    // TLS requires HTTPS
			RequiresHTTP2:              false,   // HTTP/2 not required for TLS handshake flood
			RequiresPOST:               false,
			RequiresTLS:                true,            // Must support TLS handshake
			RequiresConcurrency:        true,            // Should handle concurrent TLS handshakes
			MaxTLSHandshakeTime:        2 * time.Second, // Maximum 2 seconds for TLS handshake (faster is better)
			MinConcurrentTLSHandshakes: 8,               // Must successfully handle at least 8 concurrent TLS handshakes
		}
	default:
		return ValidationCriteria{
			RequiredStatusCodes: []int{200, 201, 202, 204},
		}
	}
}

// ScannerEndpoint wraps scanner.EndpointResult for our use
type ScannerEndpoint struct {
	Result scanner.EndpointResult
	Method string
}
