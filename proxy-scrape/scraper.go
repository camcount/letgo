package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Scrape fetches proxies from multiple sources
func (ps *ProxyScraper) Scrape(ctx context.Context) ([]ProxyResult, error) {
	sources := proxySources()
	atomic.StoreInt32(&ps.total, int32(len(sources)))
	atomic.StoreInt32(&ps.scraped, 0)

	if ps.config.OnProgress != nil {
		go ps.trackProgress(ctx)
	}

	jobs := make(chan proxySource, len(sources))
	var wg sync.WaitGroup

	for i := 0; i < ps.config.MaxThreads; i++ {
		wg.Add(1)
		go ps.scrapeWorker(ctx, jobs, &wg)
	}

	go func() {
		defer close(jobs)
		for _, source := range sources {
			select {
			case <-ctx.Done():
				return
			case jobs <- source:
			}
		}
	}()

	wg.Wait()

	return ps.GetResults(), nil
}

// scrapeWorker processes scraping jobs
func (ps *ProxyScraper) scrapeWorker(ctx context.Context, jobs <-chan proxySource, wg *sync.WaitGroup) {
	defer wg.Done()

	client := &http.Client{
		Timeout: ps.config.Timeout,
	}

	for job := range jobs {
		select {
		case <-ctx.Done():
			return
		default:
			proxies := ps.scrapeSource(client, job.URL, job.Protocol, job.Format)
			ps.addResults(proxies)
			atomic.AddInt32(&ps.scraped, 1)
		}
	}
}

// scrapeSource fetches and parses proxies from a single source
func (ps *ProxyScraper) scrapeSource(client *http.Client, sourceURL, protocol, format string) []ProxyResult {
	resp, err := client.Get(sourceURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	return ps.parseProxies(string(body), protocol, format)
}

// parseProxies extracts proxy addresses from response body
func (ps *ProxyScraper) parseProxies(body, protocol, format string) []ProxyResult {
	var results []ProxyResult

	switch format {
	case "text":
		scanner := bufio.NewScanner(strings.NewReader(body))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			parts := strings.Split(line, ":")
			if len(parts) == 2 {
				host := strings.TrimSpace(parts[0])
				port := strings.TrimSpace(parts[1])

				if net.ParseIP(host) != nil && isValidPort(port) {
					results = append(results, ProxyResult{
						Protocol: protocol,
						Host:     host,
						Port:     port,
						IsValid:  false,
					})
				}
			}
		}

	case "json":
		var jsonData []map[string]interface{}
		if err := json.Unmarshal([]byte(body), &jsonData); err == nil {
			for _, item := range jsonData {
				if host, ok := item["ip"].(string); ok {
					if port, ok := item["port"].(string); ok {
						results = append(results, ProxyResult{
							Protocol: protocol,
							Host:     host,
							Port:     port,
							IsValid:  false,
						})
					}
				}
			}
		}

	case "html":
		re := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})`)
		matches := re.FindAllStringSubmatch(body, -1)
		for _, match := range matches {
			if len(match) == 3 {
				host := match[1]
				port := match[2]
				if net.ParseIP(host) != nil && isValidPort(port) {
					results = append(results, ProxyResult{
						Protocol: protocol,
						Host:     host,
						Port:     port,
						IsValid:  false,
					})
				}
			}
		}
	}

	return results
}

// addResults adds proxy results to the collection
func (ps *ProxyScraper) addResults(results []ProxyResult) {
	if len(results) == 0 {
		return
	}

	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.results = append(ps.results, results...)
}

// GetResults returns all scraped proxy results
func (ps *ProxyScraper) GetResults() []ProxyResult {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return append([]ProxyResult{}, ps.results...)
}

// trackProgress displays scraping progress
func (ps *ProxyScraper) trackProgress(ctx context.Context) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := atomic.LoadInt32(&ps.scraped)
			total := atomic.LoadInt32(&ps.total)
			if total == 0 {
				continue
			}
			percentage := float64(current) / float64(total) * 100
			if ps.config.OnProgress != nil {
				ps.config.OnProgress(int(current), int(total), percentage)
			}
		}
	}
}
