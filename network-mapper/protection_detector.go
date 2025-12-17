package networkmapper

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// DefaultProtectionDetector implements the ProtectionDetector interface
type DefaultProtectionDetector struct {
	client     *http.Client
	cdnDB      map[string]CDNSignature
	wafDB      map[string]WAFSignature
	providerDB map[string]HostingProvider
}

// CDNSignature represents a CDN provider signature for detection
type CDNSignature struct {
	Name          string
	Headers       []string
	IPRanges      []string
	ASNs          []string
	CNAMEPatterns []string
	Confidence    float64
}

// WAFSignature represents a WAF detection signature
type WAFSignature struct {
	Name         string
	Headers      []string
	BlockPages   []string
	ErrorCodes   []int
	Fingerprints []string
	TestPayloads []string
}

// HostingProvider represents a hosting provider for identification
type HostingProvider struct {
	Name     string
	ASNs     []string
	IPRanges []string
	Domains  []string
	Features []string
}

// NewProtectionDetector creates a new protection detector with default databases
func NewProtectionDetector() *DefaultProtectionDetector {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).DialContext,
		},
	}

	return &DefaultProtectionDetector{
		client:     client,
		cdnDB:      buildCDNDatabase(),
		wafDB:      buildWAFDatabase(),
		providerDB: buildProviderDatabase(),
	}
}

// DetectProtection performs comprehensive protection service detection
func (pd *DefaultProtectionDetector) DetectProtection(ctx context.Context, target string, port int) ([]ProtectionService, error) {
	var services []ProtectionService

	// Only analyze HTTP/HTTPS services
	if port != 80 && port != 443 && port != 8080 && port != 8443 {
		return services, nil
	}

	// Get HTTP headers
	headers, err := pd.getHTTPHeaders(ctx, target, port)
	if err != nil {
		return services, fmt.Errorf("failed to get HTTP headers: %w", err)
	}

	// Detect CDN services
	cdnServices, err := pd.DetectCDN(ctx, target)
	if err == nil {
		services = append(services, cdnServices...)
	}

	// Detect WAF services
	wafServices, err := pd.DetectWAF(ctx, target, port)
	if err == nil {
		services = append(services, wafServices...)
	}

	// Analyze security headers
	securityServices, err := pd.AnalyzeSecurityHeaders(headers)
	if err == nil {
		services = append(services, securityServices...)
	}

	return services, nil
}

// AnalyzeHTTPHeaders analyzes HTTP headers for protection service signatures
func (pd *DefaultProtectionDetector) AnalyzeHTTPHeaders(headers map[string]string) ([]ProtectionService, error) {
	var services []ProtectionService

	// Normalize headers to lowercase for comparison
	normalizedHeaders := make(map[string]string)
	for k, v := range headers {
		normalizedHeaders[strings.ToLower(k)] = strings.ToLower(v)
	}

	// Check CDN signatures
	for _, signature := range pd.cdnDB {
		confidence := pd.checkCDNHeaders(normalizedHeaders, signature)
		if confidence > 0 {
			services = append(services, ProtectionService{
				Type:       ProtectionCDN,
				Name:       signature.Name,
				Confidence: confidence,
				Evidence:   pd.getCDNEvidence(normalizedHeaders, signature),
				Details:    mapToKeyValue(map[string]string{"detection_method": "http_headers"}),
			})
		}
	}

	// Check WAF signatures
	for _, signature := range pd.wafDB {
		confidence := pd.checkWAFHeaders(normalizedHeaders, signature)
		if confidence > 0 {
			services = append(services, ProtectionService{
				Type:       ProtectionWAF,
				Name:       signature.Name,
				Confidence: confidence,
				Evidence:   pd.getWAFEvidence(normalizedHeaders, signature),
				Details:    mapToKeyValue(map[string]string{"detection_method": "http_headers"}),
			})
		}
	}

	return services, nil
}

// DetectCDN specifically detects CDN services
func (pd *DefaultProtectionDetector) DetectCDN(ctx context.Context, hostname string) ([]ProtectionService, error) {
	var services []ProtectionService

	// Get HTTP headers for analysis
	headers, err := pd.getHTTPHeaders(ctx, hostname, 80)
	if err != nil {
		// Try HTTPS if HTTP fails
		headers, err = pd.getHTTPHeaders(ctx, hostname, 443)
		if err != nil {
			return services, fmt.Errorf("failed to get headers for CDN detection: %w", err)
		}
	}

	// Normalize headers
	normalizedHeaders := make(map[string]string)
	for k, v := range headers {
		normalizedHeaders[strings.ToLower(k)] = strings.ToLower(v)
	}

	// Check each CDN signature
	for _, signature := range pd.cdnDB {
		confidence := pd.checkCDNHeaders(normalizedHeaders, signature)
		
		// Also check CNAME records for additional evidence
		cnameConfidence := pd.checkCNAMEPatterns(hostname, signature)
		if cnameConfidence > 0 {
			confidence = (confidence + cnameConfidence) / 2
		}

		if confidence > 30 { // Minimum confidence threshold
			services = append(services, ProtectionService{
				Type:       ProtectionCDN,
				Name:       signature.Name,
				Confidence: confidence,
				Evidence:   pd.getCDNEvidence(normalizedHeaders, signature),
				Details: mapToKeyValue(map[string]string{
					"detection_method": "multi_layer",
					"hostname":         hostname,
				}),
			})
		}
	}

	return services, nil
}

// DetectWAF specifically detects WAF services
func (pd *DefaultProtectionDetector) DetectWAF(ctx context.Context, target string, port int) ([]ProtectionService, error) {
	var services []ProtectionService

	// Get HTTP headers
	headers, err := pd.getHTTPHeaders(ctx, target, port)
	if err != nil {
		return services, fmt.Errorf("failed to get headers for WAF detection: %w", err)
	}

	// Normalize headers
	normalizedHeaders := make(map[string]string)
	for k, v := range headers {
		normalizedHeaders[strings.ToLower(k)] = strings.ToLower(v)
	}

	// Check each WAF signature
	for _, signature := range pd.wafDB {
		confidence := pd.checkWAFHeaders(normalizedHeaders, signature)
		
		// Test with payloads for active detection
		payloadConfidence := pd.testWAFPayloads(ctx, target, port, signature)
		if payloadConfidence > 0 {
			confidence = (confidence + payloadConfidence) / 2
		}

		if confidence > 25 { // Minimum confidence threshold
			services = append(services, ProtectionService{
				Type:       ProtectionWAF,
				Name:       signature.Name,
				Confidence: confidence,
				Evidence:   pd.getWAFEvidence(normalizedHeaders, signature),
				Details: mapToKeyValue(map[string]string{
					"detection_method": "active_passive",
					"target":           target,
					"port":             fmt.Sprintf("%d", port),
				}),
			})
		}
	}

	return services, nil
}

// AnalyzeSecurityHeaders analyzes security-related HTTP headers
func (pd *DefaultProtectionDetector) AnalyzeSecurityHeaders(headers map[string]string) ([]ProtectionService, error) {
	var services []ProtectionService

	// Normalize headers
	normalizedHeaders := make(map[string]string)
	for k, v := range headers {
		normalizedHeaders[strings.ToLower(k)] = strings.ToLower(v)
	}

	// Check for security headers that indicate protection services
	securityHeaders := []string{
		"x-frame-options",
		"x-content-type-options",
		"x-xss-protection",
		"strict-transport-security",
		"content-security-policy",
		"x-permitted-cross-domain-policies",
	}

	var evidence []string
	for _, header := range securityHeaders {
		if value, exists := normalizedHeaders[header]; exists {
			evidence = append(evidence, fmt.Sprintf("%s: %s", header, value))
		}
	}

	if len(evidence) > 0 {
		services = append(services, ProtectionService{
			Type:       ProtectionFirewall,
			Name:       "Security Headers",
			Confidence: float64(len(evidence)) * 15, // 15% per security header
			Evidence:   evidence,
			Details: mapToKeyValue(map[string]string{
				"detection_method": "security_headers",
				"header_count":     fmt.Sprintf("%d", len(evidence)),
			}),
		})
	}

	return services, nil
}

// Helper methods

func (pd *DefaultProtectionDetector) getHTTPHeaders(ctx context.Context, target string, port int) (map[string]string, error) {
	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s:%d/", scheme, target, port)
	
	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := pd.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	return headers, nil
}

func (pd *DefaultProtectionDetector) checkCDNHeaders(headers map[string]string, signature CDNSignature) float64 {
	var matches int
	for _, headerPattern := range signature.Headers {
		for headerName, headerValue := range headers {
			if strings.Contains(headerName, strings.ToLower(headerPattern)) ||
				strings.Contains(headerValue, strings.ToLower(headerPattern)) {
				matches++
				break
			}
		}
	}

	if len(signature.Headers) == 0 {
		return 0
	}

	return (float64(matches) / float64(len(signature.Headers))) * 100
}

func (pd *DefaultProtectionDetector) checkWAFHeaders(headers map[string]string, signature WAFSignature) float64 {
	var matches int
	for _, headerPattern := range signature.Headers {
		for headerName, headerValue := range headers {
			if strings.Contains(headerName, strings.ToLower(headerPattern)) ||
				strings.Contains(headerValue, strings.ToLower(headerPattern)) {
				matches++
				break
			}
		}
	}

	if len(signature.Headers) == 0 {
		return 0
	}

	return (float64(matches) / float64(len(signature.Headers))) * 100
}

func (pd *DefaultProtectionDetector) checkCNAMEPatterns(hostname string, signature CDNSignature) float64 {
	// This is a simplified CNAME check - in a real implementation,
	// you would perform actual DNS CNAME lookups
	for _, pattern := range signature.CNAMEPatterns {
		if strings.Contains(hostname, pattern) {
			return 50.0 // Moderate confidence from hostname pattern
		}
	}
	return 0
}

func (pd *DefaultProtectionDetector) testWAFPayloads(ctx context.Context, target string, port int, signature WAFSignature) float64 {
	if len(signature.TestPayloads) == 0 {
		return 0
	}

	scheme := "http"
	if port == 443 || port == 8443 {
		scheme = "https"
	}

	var blocked int
	for _, payload := range signature.TestPayloads {
		url := fmt.Sprintf("%s://%s:%d/?test=%s", scheme, target, port, payload)
		
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}

		resp, err := pd.client.Do(req)
		if err != nil {
			continue
		}

		// Check if request was blocked (common WAF response codes)
		if resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 429 {
			blocked++
		}

		// Check response body for WAF block pages
		if resp.Body != nil {
			body, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err == nil {
				bodyStr := strings.ToLower(string(body))
				for _, blockPage := range signature.BlockPages {
					if strings.Contains(bodyStr, strings.ToLower(blockPage)) {
						blocked++
						break
					}
				}
			}
		}
	}

	if len(signature.TestPayloads) == 0 {
		return 0
	}

	return (float64(blocked) / float64(len(signature.TestPayloads))) * 100
}

func (pd *DefaultProtectionDetector) getCDNEvidence(headers map[string]string, signature CDNSignature) []string {
	var evidence []string
	for _, headerPattern := range signature.Headers {
		for headerName, headerValue := range headers {
			if strings.Contains(headerName, strings.ToLower(headerPattern)) ||
				strings.Contains(headerValue, strings.ToLower(headerPattern)) {
				evidence = append(evidence, fmt.Sprintf("%s: %s", headerName, headerValue))
			}
		}
	}
	return evidence
}

func (pd *DefaultProtectionDetector) getWAFEvidence(headers map[string]string, signature WAFSignature) []string {
	var evidence []string
	for _, headerPattern := range signature.Headers {
		for headerName, headerValue := range headers {
			if strings.Contains(headerName, strings.ToLower(headerPattern)) ||
				strings.Contains(headerValue, strings.ToLower(headerPattern)) {
				evidence = append(evidence, fmt.Sprintf("%s: %s", headerName, headerValue))
			}
		}
	}
	return evidence
}

// Database builders

// mapToKeyValue converts a map[string]string to []KeyValue for XML compatibility
func mapToKeyValue(m map[string]string) []KeyValue {
	var kvs []KeyValue
	for k, v := range m {
		kvs = append(kvs, KeyValue{Key: k, Value: v})
	}
	return kvs
}

func buildCDNDatabase() map[string]CDNSignature {
	return map[string]CDNSignature{
		"cloudflare": {
			Name:          "Cloudflare",
			Headers:       []string{"cf-ray", "cf-cache-status", "server: cloudflare", "cf-request-id"},
			IPRanges:      []string{"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22"},
			ASNs:          []string{"AS13335"},
			CNAMEPatterns: []string{".cloudflare.com", ".cloudflare.net"},
			Confidence:    90.0,
		},
		"fastly": {
			Name:          "Fastly",
			Headers:       []string{"fastly-debug-digest", "x-served-by", "x-cache", "x-fastly-request-id"},
			IPRanges:      []string{"23.235.32.0/20", "43.249.72.0/22"},
			ASNs:          []string{"AS54113"},
			CNAMEPatterns: []string{".fastly.com", ".fastlylb.net"},
			Confidence:    85.0,
		},
		"cloudfront": {
			Name:          "Amazon CloudFront",
			Headers:       []string{"x-amz-cf-id", "x-amz-cf-pop", "via: cloudfront", "x-amzn-requestid"},
			IPRanges:      []string{"13.32.0.0/15", "13.35.0.0/17"},
			ASNs:          []string{"AS16509"},
			CNAMEPatterns: []string{".cloudfront.net"},
			Confidence:    88.0,
		},
		"akamai": {
			Name:          "Akamai",
			Headers:       []string{"akamai-ghost-ip", "x-akamai-edgescape", "server: akamaighost"},
			IPRanges:      []string{"23.0.0.0/8", "104.64.0.0/10"},
			ASNs:          []string{"AS20940", "AS16625"},
			CNAMEPatterns: []string{".akamai.net", ".akamaiedge.net"},
			Confidence:    87.0,
		},
		"keycdn": {
			Name:          "KeyCDN",
			Headers:       []string{"server: keycdn-engine", "x-edge-location"},
			CNAMEPatterns: []string{".kxcdn.com"},
			Confidence:    80.0,
		},
		"maxcdn": {
			Name:          "MaxCDN",
			Headers:       []string{"server: netdna-cache", "x-cache"},
			CNAMEPatterns: []string{".netdna-cdn.com"},
			Confidence:    75.0,
		},
	}
}

func buildWAFDatabase() map[string]WAFSignature {
	return map[string]WAFSignature{
		"cloudflare_waf": {
			Name:         "Cloudflare WAF",
			Headers:      []string{"cf-ray", "server: cloudflare"},
			BlockPages:   []string{"attention required! | cloudflare", "ray id:", "cloudflare"},
			ErrorCodes:   []int{403, 429, 503},
			Fingerprints: []string{"cloudflare", "cf-ray"},
			TestPayloads: []string{"<script>alert(1)</script>", "' OR 1=1--", "../../../etc/passwd"},
		},
		"aws_waf": {
			Name:         "AWS WAF",
			Headers:      []string{"x-amzn-requestid", "x-amzn-errortype"},
			BlockPages:   []string{"aws waf", "request blocked"},
			ErrorCodes:   []int{403},
			Fingerprints: []string{"aws", "amazon"},
			TestPayloads: []string{"<script>", "union select", "cmd="},
		},
		"imperva": {
			Name:         "Imperva SecureSphere",
			Headers:      []string{"x-iinfo"},
			BlockPages:   []string{"imperva", "incapsula"},
			ErrorCodes:   []int{403},
			TestPayloads: []string{"<script>", "' or 1=1", "../etc/passwd"},
		},
		"f5_bigip": {
			Name:         "F5 BIG-IP ASM",
			Headers:      []string{"bigipserver", "x-waf-event-info"},
			BlockPages:   []string{"the requested url was rejected", "f5"},
			ErrorCodes:   []int{403},
			TestPayloads: []string{"<script>", "union select"},
		},
		"modsecurity": {
			Name:         "ModSecurity",
			Headers:      []string{"mod_security"},
			BlockPages:   []string{"mod_security", "not acceptable"},
			ErrorCodes:   []int{403, 406},
			TestPayloads: []string{"<script>", "' or 1=1", "union select"},
		},
		"barracuda": {
			Name:         "Barracuda WAF",
			Headers:      []string{"barra"},
			BlockPages:   []string{"barracuda", "you have been blocked"},
			ErrorCodes:   []int{403},
			TestPayloads: []string{"<script>", "../etc/passwd"},
		},
	}
}

func buildProviderDatabase() map[string]HostingProvider {
	return map[string]HostingProvider{
		"aws": {
			Name:     "Amazon Web Services",
			ASNs:     []string{"AS16509", "AS14618"},
			IPRanges: []string{"3.0.0.0/8", "13.0.0.0/8", "18.0.0.0/8"},
			Domains:  []string{".amazonaws.com", ".aws.amazon.com"},
			Features: []string{"ec2", "s3", "cloudfront", "elb"},
		},
		"gcp": {
			Name:     "Google Cloud Platform",
			ASNs:     []string{"AS15169", "AS36040"},
			IPRanges: []string{"34.64.0.0/10", "35.184.0.0/13"},
			Domains:  []string{".googleusercontent.com", ".googleapis.com"},
			Features: []string{"gce", "gcs", "gae"},
		},
		"azure": {
			Name:     "Microsoft Azure",
			ASNs:     []string{"AS8075"},
			IPRanges: []string{"13.64.0.0/11", "20.0.0.0/8"},
			Domains:  []string{".azurewebsites.net", ".azure.com"},
			Features: []string{"vm", "storage", "cdn"},
		},
	}
}