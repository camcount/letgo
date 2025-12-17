package networkmapper

import (
	"strings"
	"testing"
)

// Test CDN signature matching accuracy
func TestCDNSignatureMatchingAccuracy(t *testing.T) {
	cdnDB := GetCDNDatabase()
	
	// Test that all CDN signatures have required fields
	for key, signature := range cdnDB {
		t.Run("CDN_"+key, func(t *testing.T) {
			// Test signature completeness
			if signature.Name == "" {
				t.Errorf("CDN signature %s has empty name", key)
			}
			
			if len(signature.Headers) == 0 {
				t.Errorf("CDN signature %s has no headers", key)
			}
			
			if signature.Confidence <= 0 || signature.Confidence > 100 {
				t.Errorf("CDN signature %s has invalid confidence: %f", key, signature.Confidence)
			}
			
			// Test header format validity
			for _, header := range signature.Headers {
				if header == "" {
					t.Errorf("CDN signature %s has empty header", key)
				}
				// Headers should be lowercase for consistent matching
				if strings.ToLower(header) != header {
					t.Errorf("CDN signature %s header should be lowercase: %s", key, header)
				}
			}
			
			// Test ASN format validity
			for _, asn := range signature.ASNs {
				if !strings.HasPrefix(asn, "AS") {
					t.Errorf("CDN signature %s has invalid ASN format: %s", key, asn)
				}
			}
			
			// Test CNAME pattern validity
			for _, pattern := range signature.CNAMEPatterns {
				if pattern == "" {
					t.Errorf("CDN signature %s has empty CNAME pattern", key)
				}
				if !strings.HasPrefix(pattern, ".") {
					t.Errorf("CDN signature %s CNAME pattern should start with dot: %s", key, pattern)
				}
			}
		})
	}
	
	// Test specific CDN signature accuracy
	testCases := []struct {
		name     string
		headers  map[string]string
		expected string
	}{
		{
			name: "Cloudflare detection",
			headers: map[string]string{
				"cf-ray":         "test-ray-id",
				"server":         "cloudflare",
				"cf-cache-status": "HIT",
			},
			expected: "cloudflare",
		},
		{
			name: "Fastly detection",
			headers: map[string]string{
				"x-served-by":        "cache-server",
				"fastly-debug-digest": "test-digest",
				"x-cache":            "HIT",
			},
			expected: "fastly",
		},
		{
			name: "CloudFront detection",
			headers: map[string]string{
				"x-amz-cf-id":  "test-cf-id",
				"x-amz-cf-pop": "test-pop",
				"via":          "1.1 cloudfront",
			},
			expected: "cloudfront",
		},
		{
			name: "Akamai detection",
			headers: map[string]string{
				"akamai-ghost-ip":    "test-ip",
				"x-akamai-edgescape": "test-edgescape",
				"server":             "akamaighost",
			},
			expected: "akamai",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signature, exists := cdnDB[tc.expected]
			if !exists {
				t.Fatalf("Expected CDN signature %s not found", tc.expected)
			}
			
			// Test header matching logic
			matches := 0
			for _, headerPattern := range signature.Headers {
				for headerName, headerValue := range tc.headers {
					headerLine := strings.ToLower(headerName + ": " + headerValue)
					if strings.Contains(headerLine, strings.ToLower(headerPattern)) ||
					   strings.Contains(strings.ToLower(headerName), strings.ToLower(headerPattern)) {
						matches++
						break
					}
				}
			}
			
			if matches == 0 {
				t.Errorf("CDN signature %s should match test headers but found no matches", tc.expected)
			}
		})
	}
}

// Test WAF rule detection effectiveness
func TestWAFRuleDetectionEffectiveness(t *testing.T) {
	wafDB := GetWAFDatabase()
	
	// Test that all WAF signatures have required fields
	for key, signature := range wafDB {
		t.Run("WAF_"+key, func(t *testing.T) {
			// Test signature completeness
			if signature.Name == "" {
				t.Errorf("WAF signature %s has empty name", key)
			}
			
			if len(signature.Headers) == 0 && len(signature.BlockPages) == 0 && len(signature.Fingerprints) == 0 {
				t.Errorf("WAF signature %s has no detection methods", key)
			}
			
			// Test header format validity
			for _, header := range signature.Headers {
				if header == "" {
					t.Errorf("WAF signature %s has empty header", key)
				}
				// Headers should be lowercase for consistent matching
				if strings.ToLower(header) != header {
					t.Errorf("WAF signature %s header should be lowercase: %s", key, header)
				}
			}
			
			// Test error codes validity
			for _, code := range signature.ErrorCodes {
				if code < 100 || code > 599 {
					t.Errorf("WAF signature %s has invalid HTTP error code: %d", key, code)
				}
			}
			
			// Test fingerprints are not empty
			for _, fingerprint := range signature.Fingerprints {
				if fingerprint == "" {
					t.Errorf("WAF signature %s has empty fingerprint", key)
				}
			}
			
			// Test block pages are not empty
			for _, blockPage := range signature.BlockPages {
				if blockPage == "" {
					t.Errorf("WAF signature %s has empty block page pattern", key)
				}
			}
			
			// Test payloads are not empty
			for _, payload := range signature.TestPayloads {
				if payload == "" {
					t.Errorf("WAF signature %s has empty test payload", key)
				}
			}
		})
	}
	
	// Test specific WAF signature effectiveness
	testCases := []struct {
		name     string
		headers  map[string]string
		expected string
	}{
		{
			name: "Cloudflare WAF detection",
			headers: map[string]string{
				"cf-ray":         "test-ray-id",
				"server":         "cloudflare",
				"cf-cache-status": "HIT",
			},
			expected: "cloudflare_waf",
		},
		{
			name: "AWS WAF detection",
			headers: map[string]string{
				"x-amzn-requestid": "test-request-id",
				"x-amzn-errortype": "AccessDenied",
			},
			expected: "aws_waf",
		},
		{
			name: "Imperva detection",
			headers: map[string]string{
				"x-iinfo":    "test-info",
				"set-cookie": "incap_ses=test-session",
			},
			expected: "imperva",
		},
		{
			name: "F5 BIG-IP detection",
			headers: map[string]string{
				"bigipserver":     "test-server",
				"x-waf-event-info": "blocked",
			},
			expected: "f5_bigip",
		},
		{
			name: "ModSecurity detection",
			headers: map[string]string{
				"mod_security": "enabled",
				"server":       "apache/2.4.41",
			},
			expected: "modsecurity",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			signature, exists := wafDB[tc.expected]
			if !exists {
				t.Fatalf("Expected WAF signature %s not found", tc.expected)
			}
			
			// Test header matching logic
			matches := 0
			for _, headerPattern := range signature.Headers {
				for headerName, headerValue := range tc.headers {
					headerLine := strings.ToLower(headerName + ": " + headerValue)
					if strings.Contains(headerLine, strings.ToLower(headerPattern)) ||
					   strings.Contains(strings.ToLower(headerName), strings.ToLower(headerPattern)) {
						matches++
						break
					}
				}
			}
			
			if matches == 0 {
				t.Errorf("WAF signature %s should match test headers but found no matches", tc.expected)
			}
		})
	}
	
	// Test WAF detection with block page content
	blockPageTests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			name:     "Cloudflare block page",
			content:  "Attention Required! | Cloudflare - Ray ID: 12345",
			expected: "cloudflare_waf",
		},
		{
			name:     "AWS WAF block page",
			content:  "Request blocked by AWS WAF",
			expected: "aws_waf",
		},
		{
			name:     "Imperva block page",
			content:  "Request unsuccessful. Incapsula incident ID: 12345",
			expected: "imperva",
		},
		{
			name:     "F5 block page",
			content:  "The requested URL was rejected. Please consult with your administrator.",
			expected: "f5_bigip",
		},
	}
	
	for _, tc := range blockPageTests {
		t.Run(tc.name, func(t *testing.T) {
			signature, exists := wafDB[tc.expected]
			if !exists {
				t.Fatalf("Expected WAF signature %s not found", tc.expected)
			}
			
			// Test block page matching
			matches := 0
			for _, blockPattern := range signature.BlockPages {
				if strings.Contains(strings.ToLower(tc.content), strings.ToLower(blockPattern)) {
					matches++
					break
				}
			}
			
			if matches == 0 {
				t.Errorf("WAF signature %s should match block page content but found no matches", tc.expected)
			}
		})
	}
}

// Test hosting provider identification databases
func TestHostingProviderIdentificationDatabases(t *testing.T) {
	providerDB := GetHostingProviderDatabase()
	asnDB := GetASNInfoDatabase()
	
	// Test that all hosting provider signatures have required fields
	for key, provider := range providerDB {
		t.Run("Provider_"+key, func(t *testing.T) {
			// Test provider completeness
			if provider.Name == "" {
				t.Errorf("Hosting provider %s has empty name", key)
			}
			
			if len(provider.ASNs) == 0 && len(provider.IPRanges) == 0 && len(provider.Domains) == 0 {
				t.Errorf("Hosting provider %s has no identification methods", key)
			}
			
			// Test ASN format validity
			for _, asn := range provider.ASNs {
				if !strings.HasPrefix(asn, "AS") {
					t.Errorf("Hosting provider %s has invalid ASN format: %s", key, asn)
				}
			}
			
			// Test domain format validity
			for _, domain := range provider.Domains {
				if domain == "" {
					t.Errorf("Hosting provider %s has empty domain", key)
				}
				if !strings.HasPrefix(domain, ".") {
					t.Errorf("Hosting provider %s domain should start with dot: %s", key, domain)
				}
			}
			
			// Test features are not empty
			for _, feature := range provider.Features {
				if feature == "" {
					t.Errorf("Hosting provider %s has empty feature", key)
				}
			}
		})
	}
	
	// Test ASN database completeness
	for asn, info := range asnDB {
		t.Run("ASN_"+asn, func(t *testing.T) {
			if info.Number == "" {
				t.Errorf("ASN info %s has empty number", asn)
			}
			
			if info.Organization == "" {
				t.Errorf("ASN info %s has empty organization", asn)
			}
			
			if info.Country == "" {
				t.Errorf("ASN info %s has empty country", asn)
			}
			
			if info.Registry == "" {
				t.Errorf("ASN info %s has empty registry", asn)
			}
			
			// ASN number should match the key
			if info.Number != asn {
				t.Errorf("ASN info %s number mismatch: expected %s, got %s", asn, asn, info.Number)
			}
		})
	}
	
	// Test hosting provider lookup functionality
	testCases := []struct {
		name     string
		asn      string
		expected string
	}{
		{
			name:     "AWS identification",
			asn:      "AS16509",
			expected: "aws",
		},
		{
			name:     "Google Cloud identification",
			asn:      "AS15169",
			expected: "gcp",
		},
		{
			name:     "Azure identification",
			asn:      "AS8075",
			expected: "azure",
		},
		{
			name:     "DigitalOcean identification",
			asn:      "AS14061",
			expected: "digitalocean",
		},
		{
			name:     "Cloudflare identification",
			asn:      "AS13335",
			expected: "cloudflare",
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider := LookupHostingProvider(tc.asn, "")
			if provider == nil {
				t.Fatalf("Expected to find hosting provider for ASN %s", tc.asn)
			}
			
			// Verify the provider matches expected
			expectedProvider, exists := providerDB[tc.expected]
			if !exists {
				t.Fatalf("Expected provider %s not found in database", tc.expected)
			}
			
			if provider.Name != expectedProvider.Name {
				t.Errorf("Expected provider name %s, got %s", expectedProvider.Name, provider.Name)
			}
			
			// Verify ASN is in the provider's ASN list
			asnFound := false
			for _, providerASN := range provider.ASNs {
				if providerASN == tc.asn {
					asnFound = true
					break
				}
			}
			
			if !asnFound {
				t.Errorf("ASN %s not found in provider %s ASN list", tc.asn, provider.Name)
			}
		})
	}
	
	// Test ASN info lookup functionality
	for _, tc := range testCases {
		t.Run("ASN_Info_"+tc.name, func(t *testing.T) {
			asnInfo := LookupASNInfo(tc.asn)
			if asnInfo == nil {
				t.Fatalf("Expected to find ASN info for %s", tc.asn)
			}
			
			if asnInfo.Number != tc.asn {
				t.Errorf("Expected ASN number %s, got %s", tc.asn, asnInfo.Number)
			}
			
			if asnInfo.Organization == "" {
				t.Errorf("ASN %s should have organization information", tc.asn)
			}
			
			if asnInfo.Country == "" {
				t.Errorf("ASN %s should have country information", tc.asn)
			}
		})
	}
}

// Test database consistency and cross-references
func TestDatabaseConsistency(t *testing.T) {
	cdnDB := GetCDNDatabase()
	wafDB := GetWAFDatabase()
	providerDB := GetHostingProviderDatabase()
	asnDB := GetASNInfoDatabase()
	
	// Test that major CDN ASNs exist in ASN database (not all ASNs need to be present)
	majorCDNASNs := map[string][]string{
		"cloudflare":  {"AS13335"},
		"fastly":      {"AS54113"},
		"cloudfront":  {"AS16509"},
	}
	
	for cdnKey, asns := range majorCDNASNs {
		for _, asn := range asns {
			t.Run("CDN_ASN_"+cdnKey+"_"+asn, func(t *testing.T) {
				if _, exists := asnDB[asn]; !exists {
					t.Errorf("Major CDN %s references ASN %s which should be in ASN database", cdnKey, asn)
				}
			})
		}
	}
	
	// Test that major hosting provider ASNs exist in ASN database
	majorProviderASNs := map[string][]string{
		"aws":           {"AS16509"},
		"gcp":           {"AS15169"},
		"azure":         {"AS8075"},
		"digitalocean":  {"AS14061"},
		"cloudflare":    {"AS13335"},
	}
	
	for providerKey, asns := range majorProviderASNs {
		for _, asn := range asns {
			t.Run("Provider_ASN_"+providerKey+"_"+asn, func(t *testing.T) {
				if _, exists := asnDB[asn]; !exists {
					t.Errorf("Major hosting provider %s references ASN %s which should be in ASN database", providerKey, asn)
				}
			})
		}
	}
	
	// Test for duplicate entries across databases
	cdnNames := make(map[string]string)
	for key, cdn := range cdnDB {
		if existing, exists := cdnNames[cdn.Name]; exists {
			t.Errorf("Duplicate CDN name %s found in keys %s and %s", cdn.Name, existing, key)
		}
		cdnNames[cdn.Name] = key
	}
	
	wafNames := make(map[string]string)
	for key, waf := range wafDB {
		if existing, exists := wafNames[waf.Name]; exists {
			t.Errorf("Duplicate WAF name %s found in keys %s and %s", waf.Name, existing, key)
		}
		wafNames[waf.Name] = key
	}
	
	providerNames := make(map[string]string)
	for key, provider := range providerDB {
		if existing, exists := providerNames[provider.Name]; exists {
			t.Errorf("Duplicate provider name %s found in keys %s and %s", provider.Name, existing, key)
		}
		providerNames[provider.Name] = key
	}
}

// Test database coverage for major providers
func TestDatabaseCoverage(t *testing.T) {
	cdnDB := GetCDNDatabase()
	wafDB := GetWAFDatabase()
	providerDB := GetHostingProviderDatabase()
	
	// Test that major CDN providers are covered
	majorCDNs := []string{"cloudflare", "fastly", "cloudfront", "akamai"}
	for _, cdn := range majorCDNs {
		t.Run("Major_CDN_"+cdn, func(t *testing.T) {
			if _, exists := cdnDB[cdn]; !exists {
				t.Errorf("Major CDN provider %s not found in database", cdn)
			}
		})
	}
	
	// Test that major WAF providers are covered
	majorWAFs := []string{"cloudflare_waf", "aws_waf", "imperva", "f5_bigip", "modsecurity"}
	for _, waf := range majorWAFs {
		t.Run("Major_WAF_"+waf, func(t *testing.T) {
			if _, exists := wafDB[waf]; !exists {
				t.Errorf("Major WAF provider %s not found in database", waf)
			}
		})
	}
	
	// Test that major hosting providers are covered
	majorProviders := []string{"aws", "gcp", "azure", "digitalocean", "cloudflare"}
	for _, provider := range majorProviders {
		t.Run("Major_Provider_"+provider, func(t *testing.T) {
			if _, exists := providerDB[provider]; !exists {
				t.Errorf("Major hosting provider %s not found in database", provider)
			}
		})
	}
}