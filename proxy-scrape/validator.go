package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

// ValidateProxies tests if proxies are working
func (pv *ProxyValidator) ValidateProxies(ctx context.Context, proxies []ProxyResult) ([]ProxyResult, error) {
	atomic.StoreInt32(&pv.total, int32(len(proxies)))
	atomic.StoreInt32(&pv.validated, 0)

	if pv.config.OnProgress != nil {
		go pv.trackValidationProgress(ctx)
	}

	jobs := make(chan ProxyResult, len(proxies))
	results := make(chan ProxyResult, len(proxies))
	var wg sync.WaitGroup

	for i := 0; i < pv.config.MaxThreads; i++ {
		wg.Add(1)
		go pv.validationWorker(ctx, jobs, results, &wg)
	}

	go func() {
		defer close(jobs)
		for _, proxy := range proxies {
			select {
			case <-ctx.Done():
				return
			case jobs <- proxy:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var validProxies []ProxyResult
	for result := range results {
		// Call callback for every validated proxy (both valid and invalid)
		if pv.config.OnProxyValidated != nil {
			pv.config.OnProxyValidated(result)
		}

		if result.IsValid {
			validProxies = append(validProxies, result)
			// Call callback immediately for incremental writing
			if pv.config.OnValidProxy != nil {
				pv.config.OnValidProxy(result)
			}
		}
	}

	return validProxies, nil
}

// validationWorker validates proxy functionality
func (pv *ProxyValidator) validationWorker(ctx context.Context, jobs <-chan ProxyResult, results chan<- ProxyResult, wg *sync.WaitGroup) {
	defer wg.Done()

	for proxy := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			validatedProxy := pv.testProxy(proxy)
			results <- validatedProxy
			atomic.AddInt32(&pv.validated, 1)
		}
	}
}

// testProxy tests if a proxy is working
func (pv *ProxyValidator) testProxy(proxy ProxyResult) ProxyResult {
	proxyURL := fmt.Sprintf("%s://%s:%s", proxy.Protocol, proxy.Host, proxy.Port)

	parsedProxyURL, err := url.Parse(proxyURL)
	if err != nil {
		proxy.Error = fmt.Sprintf("invalid proxy URL: %v", err)
		return proxy
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(parsedProxyURL),
		DialContext: (&net.Dialer{
			Timeout:   pv.config.Timeout,
			KeepAlive: 0,
		}).DialContext,
		TLSHandshakeTimeout:   pv.config.Timeout,
		ResponseHeaderTimeout: pv.config.Timeout,
		DisableKeepAlives:     true,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   pv.config.Timeout,
	}

	testURL := "http://httpbin.org/ip"
	resp, err := client.Get(testURL)
	if err != nil {
		proxy.Error = fmt.Sprintf("connection failed: %v", err)
		return proxy
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		proxy.IsValid = true
		proxy.Error = ""
	} else {
		proxy.Error = fmt.Sprintf("unexpected status: %d", resp.StatusCode)
	}

	return proxy
}

// trackValidationProgress displays validation progress
func (pv *ProxyValidator) trackValidationProgress(ctx context.Context) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := atomic.LoadInt32(&pv.validated)
			total := atomic.LoadInt32(&pv.total)
			if total == 0 {
				continue
			}
			percentage := float64(current) / float64(total) * 100
			if pv.config.OnProgress != nil {
				pv.config.OnProgress(int(current), int(total), percentage)
			}
		}
	}
}
