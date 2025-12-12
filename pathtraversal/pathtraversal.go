package pathtraversal

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"
)

// Start begins the path traversal attack
func (pt *PathTraversal) Start(ctx context.Context) error {
	// Normalize and validate URL
	targetURL := NormalizeURL(pt.config.TargetURL)
	_, err := url.Parse(targetURL)
	if err != nil {
		return fmt.Errorf("invalid target URL: %v", err)
	}

	// Discover parameters if not provided
	params := pt.config.TestParameters
	if len(params) == 0 {
		params = DiscoverParameters(targetURL)
		if len(params) == 0 {
			params = CommonParameters()
		}
	}

	pt.paramsMu.Lock()
	pt.discoveredParams = params
	pt.paramsMu.Unlock()

	pt.statsMu.Lock()
	pt.stats.TotalParameters = len(params)
	pt.stats.StartTime = time.Now()
	pt.statsMu.Unlock()

	// Report initial progress immediately
	if pt.config.OnProgress != nil {
		pt.config.OnProgress(pt.GetStats())
	}

	// Get baseline response (with timeout)
	var baseline *ResponseBaseline
	if !pt.config.SkipBaselineTest {
		// Use a separate context with shorter timeout for baseline
		baselineCtx, cancel := context.WithTimeout(ctx, pt.config.Timeout)
		resp, err := pt.makeRequestWithContext(baselineCtx, targetURL, "", "")
		cancel()

		if err == nil && resp != nil {
			bodyBytes, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			baseline = &ResponseBaseline{
				StatusCode:  resp.StatusCode,
				ContentSize: len(bodyBytes),
			}
		}
	}

	// Generate payloads first to get total count
	payloads := GenerateAllPayloads()
	totalPayloads := len(payloads) * len(params)

	pt.statsMu.Lock()
	pt.stats.TotalPayloads = totalPayloads
	pt.statsMu.Unlock()

	// Create work queue for parameter+payload combinations
	type work struct {
		param   string
		payload string
	}
	workChan := make(chan work, pt.config.MaxThreads*4) // Larger buffer for better throughput

	// Start workers immediately
	for i := 0; i < pt.config.MaxThreads; i++ {
		pt.wg.Add(1)
		go func(ch <-chan work) {
			defer pt.wg.Done()
			for w := range ch {
				select {
				case <-ctx.Done():
					return
				default:
				}
				pt.testPayload(ctx, targetURL, w.param, w.payload, baseline)

				// Increment counter and report progress after EVERY payload for real-time feedback
				pt.payloadsTested.Add(1)
				if pt.config.OnProgress != nil {
					pt.config.OnProgress(pt.GetStats())
				}
			}
		}(workChan)
	}

	// Generate work items and feed to workers
	go func() {
		defer close(workChan)
		for paramIdx, param := range params {
			for _, payload := range payloads {
				select {
				case <-ctx.Done():
					return
				case workChan <- work{param: param, payload: payload}:
				}
			}
			// Update progress after each parameter is fully queued
			pt.statsMu.Lock()
			pt.stats.ParametersScanned = paramIdx + 1
			pt.statsMu.Unlock()

			if pt.config.OnProgress != nil {
				pt.config.OnProgress(pt.GetStats())
			}
		}
	}()

	// Monitor progress continuously
	go pt.monitorProgress(ctx)

	// Wait for completion
	pt.wg.Wait()

	pt.reportFinalStats()
	return nil
}

// testPayload tests a single parameter with a payload
func (pt *PathTraversal) testPayload(ctx context.Context, baseURL, param, payload string, baseline *ResponseBaseline) {
	// Build test URL
	parsedURL, _ := url.Parse(baseURL)
	query := parsedURL.Query()
	query.Set(param, payload)
	parsedURL.RawQuery = query.Encode()
	testURL := parsedURL.String()

	// Create a context with timeout for this request
	reqCtx, cancel := context.WithTimeout(ctx, pt.config.Timeout)
	defer cancel()

	// Start timing the request
	startTime := time.Now()

	// Make request using the client
	resp, err := pt.makeRequestWithContext(reqCtx, testURL, param, payload)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// Read response body with timeout
	done := make(chan []byte, 1)
	go func() {
		bodyBytes, _ := io.ReadAll(resp.Body)
		done <- bodyBytes
	}()

	var bodyBytes []byte
	select {
	case bodyBytes = <-done:
	case <-reqCtx.Done():
		return
	}

	responseTime := time.Since(startTime)

	// Analyze response
	result := AnalyzeResponse(bodyBytes, resp.StatusCode, responseTime, baseline)
	result.URL = testURL
	result.Parameter = param
	result.Payload = payload

	// Store result if vulnerable
	if result.IsVulnerable || result.Confidence > 40 {
		pt.resultsMu.Lock()
		pt.results = append(pt.results, result)
		pt.resultsMu.Unlock()

		if result.IsVulnerable {
			pt.vulnFound.Add(1)
		}
	}

	// Update stats
	atomic.AddInt64(&pt.totalResponseTime, int64(responseTime))
}

// makeRequest makes an HTTP request
func (pt *PathTraversal) makeRequest(targetURL, param, payload string) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), pt.config.Timeout)
	defer cancel()
	return pt.makeRequestWithContext(ctx, targetURL, param, payload)
}

// makeRequestWithContext makes an HTTP request with the given context
func (pt *PathTraversal) makeRequestWithContext(ctx context.Context, targetURL, param, payload string) (*http.Response, error) {
	// Create a new context with timeout if not already set
	reqCtx, cancel := context.WithTimeout(ctx, pt.config.Timeout)
	defer cancel()

	client := &http.Client{
		Timeout: pt.config.Timeout,
		Transport: &http.Transport{
			DisableCompression:    true,
			DisableKeepAlives:     true,
			MaxIdleConnsPerHost:   1,
			TLSHandshakeTimeout:   pt.config.Timeout,
			ResponseHeaderTimeout: pt.config.Timeout,
			ExpectContinueTimeout: pt.config.Timeout,
		},
	}

	// Setup proxy if configured
	if pt.config.UseProxy && len(pt.config.ProxyList) > 0 {
		proxyURL := pt.config.ProxyList[0]
		proxy, err := url.Parse(proxyURL)
		if err == nil {
			client.Transport.(*http.Transport).Proxy = http.ProxyURL(proxy)
		}
	}

	req, _ := http.NewRequestWithContext(reqCtx, "GET", targetURL, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Connection", "close")

	return client.Do(req)
}

// monitorProgress periodically reports progress
func (pt *PathTraversal) monitorProgress(ctx context.Context) {
	ticker := time.NewTicker(500 * time.Millisecond) // More frequent updates
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pt.reportProgress()
		}
	}
}

// reportProgress reports current statistics
func (pt *PathTraversal) reportProgress() {
	pt.statsMu.Lock()
	defer pt.statsMu.Unlock()

	stats := pt.GetStats()
	if pt.config.OnProgress != nil {
		pt.config.OnProgress(stats)
	}
}

// reportFinalStats reports final statistics
func (pt *PathTraversal) reportFinalStats() {
	stats := pt.GetStats()

	// Final progress update
	if pt.config.OnProgress != nil {
		pt.config.OnProgress(stats)
	}

	// Display summary
	fmt.Println()
	fmt.Println("[*] Scan completed!")
	fmt.Printf("[✓] Summary: Tested %d payloads in %v\n", stats.PayloadsTested, stats.ElapsedTime)
	if stats.VulnerabilitiesFound > 0 {
		fmt.Printf("[!] Found %d potential vulnerabilities\n\n", stats.VulnerabilitiesFound)
		fmt.Println(FormatResults(pt.GetResults()))
	} else {
		fmt.Println("[✗] No vulnerabilities found in this scan")
	}
}

// Stop gracefully stops the attack
func (pt *PathTraversal) Stop() {
	close(pt.stopChan)
}

// GetStats returns current statistics
func (pt *PathTraversal) GetStats() Stats {
	pt.statsMu.Lock()
	defer pt.statsMu.Unlock()

	elapsed := time.Since(pt.startTime)

	stats := Stats{
		PayloadsTested:       pt.payloadsTested.Load(),
		VulnerabilitiesFound: pt.vulnFound.Load(),
		TotalParameters:      pt.stats.TotalParameters,
		TotalPayloads:        pt.stats.TotalPayloads,
		ParametersScanned:    pt.stats.ParametersScanned,
		ElapsedTime:          elapsed,
		StartTime:            pt.startTime,
		LastUpdate:           time.Now(),
	}

	// Calculate average response time
	if pt.payloadsTested.Load() > 0 {
		avgNano := atomic.LoadInt64(&pt.totalResponseTime) / pt.payloadsTested.Load()
		stats.AvgResponseTime = time.Duration(avgNano)
	}

	return stats
}

// GetResults returns all discovered vulnerabilities
func (pt *PathTraversal) GetResults() []PathTraversalResult {
	pt.resultsMu.RLock()
	defer pt.resultsMu.RUnlock()

	result := make([]PathTraversalResult, len(pt.results))
	copy(result, pt.results)
	return result
}

// GetDiscoveredParameters returns the parameters that were tested
func (pt *PathTraversal) GetDiscoveredParameters() []string {
	pt.paramsMu.RLock()
	defer pt.paramsMu.RUnlock()

	result := make([]string, len(pt.discoveredParams))
	copy(result, pt.discoveredParams)
	return result
}

// SaveResultsToFile saves results to a file
func (pt *PathTraversal) SaveResultsToFile(filename string) error {
	pt.resultsMu.RLock()
	defer pt.resultsMu.RUnlock()

	var buf bytes.Buffer

	buf.WriteString("=== Path Traversal Vulnerability Report ===\n")
	buf.WriteString(fmt.Sprintf("Target: %s\n", pt.config.TargetURL))
	buf.WriteString(fmt.Sprintf("Scan Started: %s\n", pt.startTime.Format(time.RFC3339)))
	buf.WriteString(fmt.Sprintf("Vulnerabilities Found: %d\n\n", len(pt.results)))

	for _, result := range pt.results {
		buf.WriteString(fmt.Sprintf("URL: %s\n", result.URL))
		buf.WriteString(fmt.Sprintf("Parameter: %s\n", result.Parameter))
		buf.WriteString(fmt.Sprintf("Payload: %s\n", result.Payload))
		buf.WriteString(fmt.Sprintf("Status Code: %d\n", result.StatusCode))
		buf.WriteString(fmt.Sprintf("Confidence: %.1f%%\n", result.Confidence))
		buf.WriteString(fmt.Sprintf("Indicator: %s\n", result.Indicator))
		buf.WriteString(fmt.Sprintf("Evidence: %s\n", result.Evidence))
		buf.WriteString("---\n")
	}

	return nil
}
