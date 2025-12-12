package ddosscanner

import (
	"net/http"
	"time"

	"github.com/letgo/ddos"
	"github.com/letgo/scanner"
)

// ScanConfig holds configuration for target scanning
type ScanConfig struct {
	TargetURL      string
	AttackMethods  []ddos.AttackMode
	MaxThreads     int
	Timeout        time.Duration
	MaxDepth       int           // Maximum crawl depth
	MaxPages       int           // Maximum pages to crawl
	UserAgent      string
	CustomHeaders  map[string]string
	OnProgress     ProgressCallback
}

// ProgressCallback is called with progress updates
type ProgressCallback func(phase string, current, total int, percentage float64)

// EndpointResult represents a discovered endpoint with validation results
type EndpointResult struct {
	URL              string
	Method           string
	StatusCode       int
	ResponseTime     time.Duration
	ResponseSize     int64
	Headers          http.Header
	SupportsHTTP2    bool
	KeepsConnection  bool
	AcceptsLargeBody bool
	MaxBodySize      int64
	ConnectionTimeout time.Duration
	IsValid          map[ddos.AttackMode]bool // Validation result for each attack method
	ValidationErrors map[ddos.AttackMode]string // Error messages for failed validations
	CurlCommand      string // Generated cURL command
	DiscoveredBy     string // How it was discovered: "scanner", "crawler", "common", "asset"
	AssetType        string // Type of asset: "js", "css", "image", "font", "api", "html", etc.
}

// ScanResult holds all scan results
type ScanResult struct {
	TargetURL      string
	ScanStartTime  time.Time
	ScanEndTime    time.Time
	Endpoints      []EndpointResult
	ValidEndpoints map[ddos.AttackMode][]EndpointResult // Grouped by attack method
	TotalDiscovered int
	TotalValidated  int
}

// ValidationCriteria defines requirements for each attack method
type ValidationCriteria struct {
	MinResponseTime    time.Duration
	MaxResponseTime    time.Duration
	RequiredStatusCodes []int
	RequiresHTTPS      bool
	RequiresHTTP2      bool
	RequiresPOST       bool
	MinBodySize        int64
	MaxBodySize        int64
	MinConnectionTimeout time.Duration
	RequiresKeepAlive  bool
	RequiresConcurrency bool
}

// GetValidationCriteria returns criteria for a specific attack method
func GetValidationCriteria(mode ddos.AttackMode) ValidationCriteria {
	switch mode {
	case ddos.ModeFlood:
		return ValidationCriteria{
			MinResponseTime:     0,
			MaxResponseTime:     1000 * time.Millisecond, // More lenient for assets (1 second)
			RequiredStatusCodes: []int{200, 201, 202, 204, 304}, // 304 Not Modified is good for cached assets
			RequiresHTTPS:       false,
			RequiresHTTP2:       false,
			RequiresPOST:        false,
			RequiresConcurrency: true,
		}
	case ddos.ModeSlowloris:
		return ValidationCriteria{
			MinResponseTime:        0,
			MaxResponseTime:        30 * time.Second,
			RequiredStatusCodes:    []int{200, 201, 202, 204},
			RequiresHTTPS:          false,
			RequiresHTTP2:          false,
			RequiresPOST:           false,
			MinConnectionTimeout:    10 * time.Second,
			RequiresKeepAlive:       true,
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
			MinBodySize:         1024 * 1024, // 1MB minimum
			MaxBodySize:         10 * 1024 * 1024, // 10MB maximum
		}
	case ddos.ModeMixed:
		return ValidationCriteria{
			MinResponseTime:        0,
			MaxResponseTime:        500 * time.Millisecond,
			RequiredStatusCodes:    []int{200, 201, 202, 204},
			RequiresHTTPS:           false,
			RequiresHTTP2:           false,
			RequiresPOST:            false,
			MinConnectionTimeout:    10 * time.Second,
			RequiresKeepAlive:       true,
			RequiresConcurrency:     true,
		}
	default:
		return ValidationCriteria{
			RequiredStatusCodes: []int{200, 201, 202, 204},
		}
	}
}

// CrawlResult represents a discovered page from crawling
type CrawlResult struct {
	URL        string
	Depth      int
	Links      []string
	StatusCode int
	IsValid    bool
}

// ScannerEndpoint wraps scanner.EndpointResult for our use
type ScannerEndpoint struct {
	Result scanner.EndpointResult
	Method string
}

