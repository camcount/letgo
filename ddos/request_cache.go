package ddos

import (
	"net/http"
	"sync"
	"sync/atomic"
)

// RequestCache pre-builds and caches HTTP requests for zero-copy sending
type RequestCache struct {
	cachedRequests []*http.Request
	cacheSize      int
	index          int64
	mu             sync.RWMutex
	builder        *RequestBuilder
}

// NewRequestCache creates a new request cache
func NewRequestCache(builder *RequestBuilder, cacheSize int) *RequestCache {
	if cacheSize <= 0 {
		cacheSize = 10000
	}

	cache := &RequestCache{
		cacheSize: cacheSize,
		builder:   builder,
	}

	// Pre-build requests
	cache.PreBuildRequests(cacheSize)

	return cache
}

// PreBuildRequests pre-builds N requests
func (rc *RequestCache) PreBuildRequests(count int) {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	rc.cachedRequests = make([]*http.Request, 0, count)

	for i := 0; i < count; i++ {
		req, err := rc.builder.BuildRequest()
		if err != nil {
			continue
		}
		rc.cachedRequests = append(rc.cachedRequests, req)
	}
}

// GetRequest returns the next cached request (round-robin)
func (rc *RequestCache) GetRequest() *http.Request {
	rc.mu.RLock()
	defer rc.mu.RUnlock()

	if len(rc.cachedRequests) == 0 {
		// Fallback to building on demand
		req, _ := rc.builder.BuildRequest()
		return req
	}

	idx := atomic.AddInt64(&rc.index, 1) - 1
	return rc.cachedRequests[int(idx)%len(rc.cachedRequests)]
}

// Refresh refreshes the cache with new requests
func (rc *RequestCache) Refresh() {
	rc.PreBuildRequests(rc.cacheSize)
}

