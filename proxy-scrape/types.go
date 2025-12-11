package proxy

import (
	"sync"
	"time"
)

// ProxyScraperConfig holds configuration for the proxy scraper
type ProxyScraperConfig struct {
	MaxThreads       int
	Timeout          time.Duration
	OnProgress       func(scraped, total int, percentage float64)
	OnValidProxy     func(proxy ProxyResult)
	OnProxyValidated func(proxy ProxyResult)
}

// ProxyResult represents a scraped proxy
type ProxyResult struct {
	Protocol string
	Host     string
	Port     string
	IsValid  bool
	Error    string
}

// ProxyScraper handles proxy scraping operations
type ProxyScraper struct {
	config  ProxyScraperConfig
	results []ProxyResult
	mu      sync.Mutex
	scraped int32
	total   int32
}

// ProxyValidator handles proxy validation operations
type ProxyValidator struct {
	config    ProxyScraperConfig
	validated int32
	total     int32
}

// New creates a new ProxyScraper instance
func New(config ProxyScraperConfig) *ProxyScraper {
	if config.MaxThreads <= 0 {
		config.MaxThreads = 50
	}
	if config.Timeout <= 0 {
		config.Timeout = 15 * time.Second
	}

	return &ProxyScraper{
		config:  config,
		results: make([]ProxyResult, 0),
	}
}

// NewValidator creates a new ProxyValidator instance
func NewValidator(config ProxyScraperConfig) *ProxyValidator {
	if config.MaxThreads <= 0 {
		config.MaxThreads = 20
	}
	if config.Timeout <= 0 {
		config.Timeout = 10 * time.Second
	}

	return &ProxyValidator{
		config: config,
	}
}
