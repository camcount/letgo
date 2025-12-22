package ddos

import (
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ProxyHealth tracks the health status of a proxy
type ProxyHealth struct {
	proxy          string
	failures       int64
	successes      int64
	lastFailure    int64 // Unix timestamp in nanoseconds
	lastSuccess    int64 // Unix timestamp in nanoseconds
	disabled       int32 // Atomic: 0 = enabled, 1 = disabled
	disabledUntil  int64 // Unix timestamp in nanoseconds when proxy can be retried
	responseTime   int64 // Average response time in nanoseconds
	requestCount   int64 // Total requests through this proxy
}

// ProxyManager manages proxy health, selection, and recovery
type ProxyManager struct {
	proxies     []string
	health      map[string]*ProxyHealth
	mu          sync.RWMutex
	failLimit   int
	cooldown    time.Duration
	recoveryTime time.Duration
	
	// Selection strategy
	selectionIndex int64 // Atomic counter for round-robin
	useWeightedSelection bool
}

// NewProxyManager creates a new proxy manager with optimized settings
func NewProxyManager(proxyList []string) *ProxyManager {
	if len(proxyList) == 0 {
		return nil
	}

	pm := &ProxyManager{
		proxies:              make([]string, 0, len(proxyList)),
		health:               make(map[string]*ProxyHealth, len(proxyList)),
		failLimit:            10,                   // Increased from 3 to 10 for less aggressive disabling
		cooldown:             5 * time.Second,      // Reduced from 10s to 5s for faster recovery
		recoveryTime:         30 * time.Second,    // Recovery window
		useWeightedSelection: len(proxyList) > 10, // Use weighted selection for large lists
	}

	// Initialize health tracking for all proxies with lightweight validation
	for _, proxy := range proxyList {
		// Validate proxy URL format (lightweight check)
		if !isValidProxyURL(proxy) {
			continue // Skip invalid proxies
		}
		pm.proxies = append(pm.proxies, proxy)
		pm.health[proxy] = &ProxyHealth{
			proxy: proxy,
		}
	}

	return pm
}

// GetNextProxy returns the next healthy proxy using optimized selection
func (pm *ProxyManager) GetNextProxy() (string, bool) {
	if pm == nil || len(pm.proxies) == 0 {
		return "", false
	}

	now := time.Now().UnixNano()
	maxAttempts := len(pm.proxies) * 2 // Allow up to 2 rounds to find a proxy
	attempts := 0
	
	// Try to find a healthy proxy (with max attempts to prevent infinite loops)
	for attempts < maxAttempts {
		attempts++
		var proxy string
		
		if pm.useWeightedSelection {
			proxy = pm.selectWeightedProxy()
		} else {
			proxy = pm.selectRoundRobinProxy()
		}

		if proxy == "" {
			continue
		}

		pm.mu.RLock()
		health := pm.health[proxy]
		pm.mu.RUnlock()

		if health == nil {
			continue
		}

		// Check if proxy is disabled
		if atomic.LoadInt32(&health.disabled) == 1 {
			// Check if cooldown period has passed
			disabledUntil := atomic.LoadInt64(&health.disabledUntil)
			if now < disabledUntil {
				continue // Still in cooldown
			}
			// Cooldown passed, try to re-enable
			if atomic.CompareAndSwapInt32(&health.disabled, 1, 0) {
				atomic.StoreInt64(&health.failures, 0) // Reset failure count
			}
		}

		// Proxy is healthy
		return proxy, true
	}

	// If all proxies are disabled, try to re-enable one after cooldown
	// This prevents complete deadlock when all proxies are temporarily disabled
	pm.mu.RLock()
	for _, proxy := range pm.proxies {
		health := pm.health[proxy]
		if health == nil {
			continue
		}
		if atomic.LoadInt32(&health.disabled) == 1 {
			disabledUntil := atomic.LoadInt64(&health.disabledUntil)
			if now >= disabledUntil {
				// Force re-enable after cooldown
				atomic.StoreInt32(&health.disabled, 0)
				atomic.StoreInt64(&health.failures, 0)
				pm.mu.RUnlock()
				return proxy, true
			}
		}
	}
	pm.mu.RUnlock()

	return "", false
}

// selectRoundRobinProxy selects proxy using round-robin (lightweight)
func (pm *ProxyManager) selectRoundRobinProxy() string {
	idx := atomic.AddInt64(&pm.selectionIndex, 1) - 1
	return pm.proxies[int(idx)%len(pm.proxies)]
}

// selectWeightedProxy selects proxy based on performance (for large lists)
func (pm *ProxyManager) selectWeightedProxy() string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// Find proxies with best performance (lowest response time, highest success rate)
	bestProxy := pm.proxies[0]
	bestScore := pm.calculateScore(pm.health[bestProxy])

	for _, proxy := range pm.proxies[1:] {
		health := pm.health[proxy]
		if health == nil {
			continue
		}
		score := pm.calculateScore(health)
		if score > bestScore {
			bestScore = score
			bestProxy = proxy
		}
	}

	return bestProxy
}

// calculateScore calculates a performance score for proxy selection
func (pm *ProxyManager) calculateScore(health *ProxyHealth) float64 {
	if health == nil {
		return 0
	}

	successes := atomic.LoadInt64(&health.successes)
	failures := atomic.LoadInt64(&health.failures)
	total := successes + failures

	if total == 0 {
		return 1.0 // Default score for unused proxies
	}

	// Success rate (0-1)
	successRate := float64(successes) / float64(total)

	// Response time factor (lower is better, normalized)
	avgResponseTime := atomic.LoadInt64(&health.responseTime)
	timeFactor := 1.0
	if avgResponseTime > 0 {
		// Normalize: 1s = 0.5, 0s = 1.0
		timeFactor = 1.0 / (1.0 + float64(avgResponseTime)/1e9)
	}

	// Combined score: success rate * time factor
	return successRate * timeFactor
}

// MarkSuccess records a successful request through a proxy
func (pm *ProxyManager) MarkSuccess(proxy string, responseTime time.Duration) {
	if pm == nil || proxy == "" {
		return
	}

	pm.mu.RLock()
	health := pm.health[proxy]
	pm.mu.RUnlock()

	if health == nil {
		return
	}

	now := time.Now().UnixNano()
	atomic.AddInt64(&health.successes, 1)
	atomic.StoreInt64(&health.lastSuccess, now)
	atomic.StoreInt32(&health.disabled, 0) // Re-enable if it was disabled

	// Update average response time (exponential moving average for efficiency)
	oldTime := atomic.LoadInt64(&health.responseTime)
	if oldTime == 0 {
		atomic.StoreInt64(&health.responseTime, int64(responseTime))
	} else {
		// EMA: new = old * 0.7 + new * 0.3
		newTime := int64(float64(oldTime)*0.7 + float64(responseTime)*0.3)
		atomic.StoreInt64(&health.responseTime, newTime)
	}

	atomic.AddInt64(&health.requestCount, 1)
}

// MarkFailure records a failed request through a proxy
func (pm *ProxyManager) MarkFailure(proxy string) {
	if pm == nil || proxy == "" {
		return
	}

	pm.mu.RLock()
	health := pm.health[proxy]
	pm.mu.RUnlock()

	if health == nil {
		return
	}

	now := time.Now().UnixNano()
	failures := atomic.AddInt64(&health.failures, 1)
	atomic.StoreInt64(&health.lastFailure, now)
	atomic.AddInt64(&health.requestCount, 1)

	// Exponential backoff: disable proxy if failure limit reached
	// Cooldown increases with consecutive failures for better recovery
	if failures >= int64(pm.failLimit) {
		if atomic.CompareAndSwapInt32(&health.disabled, 0, 1) {
			// Exponential backoff: cooldown = base * 2^(failures/failLimit)
			// Cap at 5x base cooldown to prevent excessive wait times
			backoffMultiplier := int64(1)
			if failures > int64(pm.failLimit) {
				backoffMultiplier = (failures / int64(pm.failLimit))
				if backoffMultiplier > 5 {
					backoffMultiplier = 5 // Cap at 5x
				}
			}
			cooldownDuration := time.Duration(backoffMultiplier) * pm.cooldown
			atomic.StoreInt64(&health.disabledUntil, now+cooldownDuration.Nanoseconds())
		}
	}
}

// GetActiveProxies returns the number of active (non-disabled) proxies
func (pm *ProxyManager) GetActiveProxies() int {
	if pm == nil {
		return 0
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	active := 0
	now := time.Now().UnixNano()
	for _, health := range pm.health {
		if atomic.LoadInt32(&health.disabled) == 0 {
			active++
		} else {
			// Check if cooldown expired
			if now >= atomic.LoadInt64(&health.disabledUntil) {
				active++ // Will be re-enabled on next use
			}
		}
	}
	return active
}

// GetDisabledProxies returns the number of disabled proxies
func (pm *ProxyManager) GetDisabledProxies() int {
	if pm == nil {
		return 0
	}

	total := len(pm.proxies)
	active := pm.GetActiveProxies()
	return total - active
}

// GetStats returns proxy health statistics
func (pm *ProxyManager) GetStats() map[string]interface{} {
	if pm == nil {
		return nil
	}

	pm.mu.RLock()
	defer pm.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["total"] = len(pm.proxies)
	stats["active"] = pm.GetActiveProxies()
	stats["disabled"] = pm.GetDisabledProxies()

	// Calculate average success rate
	totalSuccesses := int64(0)
	totalFailures := int64(0)
	for _, health := range pm.health {
		totalSuccesses += atomic.LoadInt64(&health.successes)
		totalFailures += atomic.LoadInt64(&health.failures)
	}

	totalRequests := totalSuccesses + totalFailures
	if totalRequests > 0 {
		stats["success_rate"] = float64(totalSuccesses) / float64(totalRequests)
	} else {
		stats["success_rate"] = 0.0
	}

	return stats
}

// isValidProxyURL performs lightweight validation of proxy URL format
func isValidProxyURL(proxy string) bool {
	if proxy == "" {
		return false
	}
	
	// Quick format check: must contain :// or : (for IP:port format)
	if !strings.Contains(proxy, "://") && !strings.Contains(proxy, ":") {
		return false
	}
	
	// Try parsing to validate structure
	parsed, err := url.Parse(proxy)
	if err != nil {
		return false
	}
	
	// Must have a scheme or be IP:port format
	if parsed.Scheme == "" {
		// IP:port format - validate basic structure
		return strings.Contains(proxy, ":") && len(proxy) > 3
	}
	
	// Supported schemes
	supportedSchemes := []string{"http", "https", "socks5", "socks4"}
	for _, scheme := range supportedSchemes {
		if parsed.Scheme == scheme {
			return true
		}
	}
	
	return false
}

