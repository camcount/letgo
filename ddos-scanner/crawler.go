package ddosscanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"time"
)

// Crawler handles web crawling to discover links and pages
type Crawler struct {
	config      ScanConfig
	visited     map[string]bool
	visitedMu   sync.Mutex
	baseURL     *url.URL
	client      *http.Client
	linkRegex   *regexp.Regexp
}

// NewCrawler creates a new crawler instance
func NewCrawler(config ScanConfig) (*Crawler, error) {
	baseURL, err := url.Parse(config.TargetURL)
	if err != nil {
		return nil, fmt.Errorf("invalid target URL: %w", err)
	}

	// Compile regex for finding links
	linkRegex := regexp.MustCompile(`(?i)<a[^>]+href=["']([^"']+)["']`)

	client := &http.Client{
		Timeout: config.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Follow redirects but limit to 5
			if len(via) >= 5 {
				return fmt.Errorf("stopped after 5 redirects")
			}
			return nil
		},
	}

	return &Crawler{
		config:    config,
		visited:   make(map[string]bool),
		baseURL:   baseURL,
		client:    client,
		linkRegex: linkRegex,
	}, nil
}

// Crawl discovers pages by following links
func (c *Crawler) Crawl(ctx context.Context) ([]CrawlResult, error) {
	var results []CrawlResult
	queue := make(chan string, 100)
	resultsChan := make(chan CrawlResult, 100)
	var wg sync.WaitGroup

	// Start with base URL
	queue <- c.config.TargetURL
	c.markVisited(c.config.TargetURL)

	// Start workers
	for i := 0; i < c.config.MaxThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.crawlWorker(ctx, queue, resultsChan)
		}()
	}

	// Collect results
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Process queue
	go func() {
		defer close(queue)
		depth := 0
		currentLevel := []string{c.config.TargetURL}
		nextLevel := []string{}

		for depth < c.config.MaxDepth && len(results) < c.config.MaxPages {
			for _, urlStr := range currentLevel {
				select {
				case <-ctx.Done():
					return
				case queue <- urlStr:
				}
			}

			// Wait for current level to complete
			timeout := time.After(5 * time.Second)
			levelComplete := false
			for !levelComplete {
				select {
				case result := <-resultsChan:
					results = append(results, result)
					// Add discovered links to next level
					for _, link := range result.Links {
						if !c.isVisited(link) && IsSameDomainOrSubdomain(link, c.config.TargetURL) {
							nextLevel = append(nextLevel, link)
							c.markVisited(link)
						}
					}
					if len(results) >= c.config.MaxPages {
						return
					}
				case <-timeout:
					levelComplete = true
				case <-ctx.Done():
					return
				}
			}

			if len(nextLevel) == 0 {
				break
			}

			currentLevel = nextLevel
			nextLevel = []string{}
			depth++
		}
	}()

	// Collect remaining results
	for result := range resultsChan {
		results = append(results, result)
		if len(results) >= c.config.MaxPages {
			break
		}
	}

	return results, nil
}

// crawlWorker processes URLs from the queue
func (c *Crawler) crawlWorker(ctx context.Context, queue <-chan string, results chan<- CrawlResult) {
	for urlStr := range queue {
		select {
		case <-ctx.Done():
			return
		default:
			result := c.crawlPage(ctx, urlStr, 0)
			if result.IsValid {
				results <- result
			}
		}
	}
}

// crawlPage crawls a single page and extracts links
func (c *Crawler) crawlPage(ctx context.Context, urlStr string, depth int) CrawlResult {
	result := CrawlResult{
		URL:   urlStr,
		Depth: depth,
		Links: []string{},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		return result
	}

	// Set headers
	req.Header.Set("User-Agent", c.config.UserAgent)
	if c.config.CustomHeaders != nil {
		for k, v := range c.config.CustomHeaders {
			req.Header.Set(k, v)
		}
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.IsValid = resp.StatusCode >= 200 && resp.StatusCode < 400

	// Read body and extract links
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 100*1024)) // Limit to 100KB
	if err != nil {
		return result
	}

	body := string(bodyBytes)
	result.Links = c.extractLinks(body, urlStr)

	return result
}

// extractLinks extracts all links from HTML content
func (c *Crawler) extractLinks(html, baseURL string) []string {
	var links []string
	seen := make(map[string]bool)

	matches := c.linkRegex.FindAllStringSubmatch(html, -1)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}

		link := match[1]
		// Resolve relative URLs
		absoluteURL, err := c.resolveURL(baseURL, link)
		if err != nil {
			continue
		}

		// Normalize URL
		normalized, err := NormalizeURL(absoluteURL)
		if err != nil {
			continue
		}

		// Only include same-domain links
		if IsSameDomainOrSubdomain(normalized, c.config.TargetURL) && !seen[normalized] {
			links = append(links, normalized)
			seen[normalized] = true
		}
	}

	return links
}

// resolveURL resolves a relative URL against a base URL
func (c *Crawler) resolveURL(baseURL, relativeURL string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}

	relative, err := url.Parse(relativeURL)
	if err != nil {
		return "", err
	}

	return base.ResolveReference(relative).String(), nil
}

// markVisited marks a URL as visited
func (c *Crawler) markVisited(urlStr string) {
	c.visitedMu.Lock()
	defer c.visitedMu.Unlock()
	c.visited[urlStr] = true
}

// isVisited checks if a URL has been visited
func (c *Crawler) isVisited(urlStr string) bool {
	c.visitedMu.Lock()
	defer c.visitedMu.Unlock()
	return c.visited[urlStr]
}

