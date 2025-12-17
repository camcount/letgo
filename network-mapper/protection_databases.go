package networkmapper

import (
	"regexp"
)

// CDNDatabase contains comprehensive CDN provider signatures
var CDNDatabase = map[string]CDNSignature{
	"cloudflare": {
		Name:          "Cloudflare",
		Headers:       []string{"cf-ray", "cf-cache-status", "server: cloudflare", "cf-request-id", "cf-connecting-ip", "cf-ipcountry", "cf-visitor"},
		IPRanges:      []string{"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"},
		ASNs:          []string{"AS13335"},
		CNAMEPatterns: []string{".cloudflare.com", ".cloudflare.net", ".cloudflare-dns.com"},
		Confidence:    95.0,
	},
	"fastly": {
		Name:          "Fastly",
		Headers:       []string{"fastly-debug-digest", "x-served-by", "x-cache", "x-fastly-request-id", "fastly-debug-path", "x-timer", "x-cache-hits"},
		IPRanges:      []string{"23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23", "103.245.224.0/24", "104.156.80.0/20", "146.75.0.0/16", "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17", "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20", "172.111.64.0/18", "185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16"},
		ASNs:          []string{"AS54113"},
		CNAMEPatterns: []string{".fastly.com", ".fastlylb.net", ".fastly.map.fastly.net"},
		Confidence:    90.0,
	},
	"cloudfront": {
		Name:          "Amazon CloudFront",
		Headers:       []string{"x-amz-cf-id", "x-amz-cf-pop", "via: cloudfront", "x-amzn-requestid", "x-amz-request-id", "x-cache"},
		IPRanges:      []string{"13.32.0.0/15", "13.35.0.0/17", "18.160.0.0/15", "52.222.128.0/17", "54.182.0.0/16", "54.192.0.0/16", "54.230.0.0/16", "54.239.128.0/18", "54.239.192.0/19", "54.240.128.0/18", "99.84.0.0/16", "205.251.192.0/19", "216.137.32.0/19"},
		ASNs:          []string{"AS16509"},
		CNAMEPatterns: []string{".cloudfront.net", ".amazonaws.com"},
		Confidence:    92.0,
	},
	"akamai": {
		Name:          "Akamai",
		Headers:       []string{"akamai-ghost-ip", "x-akamai-edgescape", "server: akamaighost", "x-akamai-request-id", "akamai-origin-hop", "x-check-cacheable"},
		IPRanges:      []string{"23.0.0.0/8", "104.64.0.0/10", "184.24.0.0/13", "184.50.0.0/15", "184.84.0.0/14", "2.16.0.0/13", "23.32.0.0/11", "23.64.0.0/14", "23.72.0.0/13", "96.6.0.0/15", "184.26.0.0/15", "184.28.0.0/14", "184.30.0.0/15"},
		ASNs:          []string{"AS20940", "AS16625", "AS12222", "AS21342", "AS21357", "AS31107", "AS31108", "AS31109", "AS31110", "AS31377"},
		CNAMEPatterns: []string{".akamai.net", ".akamaiedge.net", ".akamaihd.net", ".akamaitechnologies.com"},
		Confidence:    88.0,
	},
	"keycdn": {
		Name:          "KeyCDN",
		Headers:       []string{"server: keycdn-engine", "x-edge-location", "x-cache", "keycdn-cache"},
		IPRanges:      []string{"104.25.0.0/16", "185.254.196.0/22"},
		ASNs:          []string{"AS30148"},
		CNAMEPatterns: []string{".kxcdn.com", ".keycdn.com"},
		Confidence:    85.0,
	},
	"maxcdn": {
		Name:          "MaxCDN",
		Headers:       []string{"server: netdna-cache", "x-cache", "x-edge-location"},
		CNAMEPatterns: []string{".netdna-cdn.com", ".maxcdn.com"},
		Confidence:    80.0,
	},
	"jsdelivr": {
		Name:          "jsDelivr",
		Headers:       []string{"x-served-by", "x-cache", "cf-ray"},
		CNAMEPatterns: []string{".jsdelivr.net"},
		Confidence:    75.0,
	},
	"bunnycdn": {
		Name:          "BunnyCDN",
		Headers:       []string{"server: bunnycdn", "cdn-pullzone", "cdn-requestcountrycode"},
		CNAMEPatterns: []string{".b-cdn.net"},
		Confidence:    82.0,
	},
	"stackpath": {
		Name:          "StackPath",
		Headers:       []string{"x-sp-edge-server", "x-served-by"},
		CNAMEPatterns: []string{".stackpathdns.com"},
		Confidence:    78.0,
	},
	"azure_cdn": {
		Name:          "Azure CDN",
		Headers:       []string{"x-azure-ref", "x-cache", "server: microsoft-iis"},
		CNAMEPatterns: []string{".azureedge.net", ".vo.msecnd.net"},
		Confidence:    85.0,
	},
	"google_cdn": {
		Name:          "Google Cloud CDN",
		Headers:       []string{"via: 1.1 google", "x-goog-generation", "x-goog-metageneration"},
		CNAMEPatterns: []string{".googleusercontent.com", ".googleapis.com"},
		Confidence:    87.0,
	},
}

// WAFDatabase contains comprehensive WAF detection signatures
var WAFDatabase = map[string]WAFSignature{
	"cloudflare_waf": {
		Name:         "Cloudflare WAF",
		Headers:      []string{"cf-ray", "server: cloudflare", "cf-cache-status"},
		BlockPages:   []string{"attention required! | cloudflare", "ray id:", "cloudflare", "checking your browser", "ddos protection by cloudflare"},
		ErrorCodes:   []int{403, 429, 503, 520, 521, 522, 523, 524, 525, 526, 527, 530},
		Fingerprints: []string{"cloudflare", "cf-ray", "ddos protection"},
		TestPayloads: []string{"<script>alert(1)</script>", "' OR 1=1--", "../../../etc/passwd", "union select", "cmd=whoami"},
	},
	"aws_waf": {
		Name:         "AWS WAF",
		Headers:      []string{"x-amzn-requestid", "x-amzn-errortype", "x-amzn-trace-id"},
		BlockPages:   []string{"aws waf", "request blocked", "forbidden", "access denied"},
		ErrorCodes:   []int{403, 429},
		Fingerprints: []string{"aws", "amazon", "amzn"},
		TestPayloads: []string{"<script>", "union select", "cmd=", "../etc/passwd", "' or 1=1"},
	},
	"imperva": {
		Name:         "Imperva SecureSphere",
		Headers:      []string{"x-iinfo", "set-cookie: incap_ses"},
		BlockPages:   []string{"imperva", "incapsula", "request unsuccessful", "incident id"},
		ErrorCodes:   []int{403, 406},
		Fingerprints: []string{"imperva", "incapsula", "incap_ses"},
		TestPayloads: []string{"<script>", "' or 1=1", "../etc/passwd", "union select"},
	},
	"f5_bigip": {
		Name:         "F5 BIG-IP ASM",
		Headers:      []string{"bigipserver", "x-waf-event-info", "server: bigip"},
		BlockPages:   []string{"the requested url was rejected", "f5", "bigip", "your request was rejected"},
		ErrorCodes:   []int{403, 406},
		Fingerprints: []string{"f5", "bigip", "asm"},
		TestPayloads: []string{"<script>", "union select", "../etc/passwd"},
	},
	"modsecurity": {
		Name:         "ModSecurity",
		Headers:      []string{"mod_security", "server: apache"},
		BlockPages:   []string{"mod_security", "not acceptable", "forbidden", "406 not acceptable"},
		ErrorCodes:   []int{403, 406, 501},
		Fingerprints: []string{"mod_security", "modsecurity"},
		TestPayloads: []string{"<script>", "' or 1=1", "union select", "../etc/passwd"},
	},
	"barracuda": {
		Name:         "Barracuda WAF",
		Headers:      []string{"barra", "server: barracuda"},
		BlockPages:   []string{"barracuda", "you have been blocked", "access denied"},
		ErrorCodes:   []int{403, 404},
		Fingerprints: []string{"barracuda", "barra"},
		TestPayloads: []string{"<script>", "../etc/passwd", "union select"},
	},
	"fortinet": {
		Name:         "Fortinet FortiWeb",
		Headers:      []string{"fortigate", "x-fw-debug"},
		BlockPages:   []string{"fortigate", "fortinet", "blocked by fortigate"},
		ErrorCodes:   []int{403},
		Fingerprints: []string{"fortinet", "fortigate", "fortiweb"},
		TestPayloads: []string{"<script>", "' or 1=1", "../etc/passwd"},
	},
	"sucuri": {
		Name:         "Sucuri CloudProxy",
		Headers:      []string{"x-sucuri-id", "server: sucuri/cloudproxy"},
		BlockPages:   []string{"sucuri", "access denied", "blocked by sucuri"},
		ErrorCodes:   []int{403},
		Fingerprints: []string{"sucuri", "cloudproxy"},
		TestPayloads: []string{"<script>", "union select", "../etc/passwd"},
	},
	"wordfence": {
		Name:         "Wordfence",
		Headers:      []string{"x-wordfence-blocked"},
		BlockPages:   []string{"wordfence", "blocked by wordfence", "your access to this site has been limited"},
		ErrorCodes:   []int{403, 503},
		Fingerprints: []string{"wordfence"},
		TestPayloads: []string{"<script>", "../wp-config.php", "union select"},
	},
	"akamai_kona": {
		Name:         "Akamai Kona Site Defender",
		Headers:      []string{"akamai-ghost-ip", "x-akamai-edgescape"},
		BlockPages:   []string{"reference #", "access denied", "akamai"},
		ErrorCodes:   []int{403},
		Fingerprints: []string{"akamai", "kona"},
		TestPayloads: []string{"<script>", "' or 1=1", "../etc/passwd"},
	},
	"azure_waf": {
		Name:         "Azure Web Application Firewall",
		Headers:      []string{"x-azure-ref", "server: microsoft-iis"},
		BlockPages:   []string{"azure", "access denied", "blocked by azure waf"},
		ErrorCodes:   []int{403},
		Fingerprints: []string{"azure", "microsoft"},
		TestPayloads: []string{"<script>", "union select", "../etc/passwd"},
	},
	"citrix_netscaler": {
		Name:         "Citrix NetScaler",
		Headers:      []string{"ns_af", "citrix_ns_id", "set-cookie: ns_af"},
		BlockPages:   []string{"netscaler", "citrix", "access denied"},
		ErrorCodes:   []int{403},
		Fingerprints: []string{"netscaler", "citrix"},
		TestPayloads: []string{"<script>", "' or 1=1", "../etc/passwd"},
	},
}

// LoadBalancerDatabase contains load balancer detection signatures
var LoadBalancerDatabase = map[string]LoadBalancerSignature{
	"aws_elb": {
		Name:         "AWS Elastic Load Balancer",
		Headers:      []string{"x-amzn-trace-id", "x-forwarded-proto"},
		Fingerprints: []string{"elb", "amazonaws"},
		Confidence:   85.0,
	},
	"aws_alb": {
		Name:         "AWS Application Load Balancer",
		Headers:      []string{"x-amzn-trace-id", "x-forwarded-proto"},
		Fingerprints: []string{"alb", "amazonaws"},
		Confidence:   85.0,
	},
	"gcp_lb": {
		Name:         "Google Cloud Load Balancer",
		Headers:      []string{"via: 1.1 google", "x-cloud-trace-context"},
		Fingerprints: []string{"google", "gcp"},
		Confidence:   80.0,
	},
	"azure_lb": {
		Name:         "Azure Load Balancer",
		Headers:      []string{"x-azure-ref", "x-forwarded-proto"},
		Fingerprints: []string{"azure", "microsoft"},
		Confidence:   80.0,
	},
	"nginx": {
		Name:         "Nginx Load Balancer",
		Headers:      []string{"server: nginx", "x-upstream-cache-status"},
		Fingerprints: []string{"nginx"},
		Confidence:   70.0,
	},
	"haproxy": {
		Name:         "HAProxy",
		Headers:      []string{"server: haproxy"},
		Fingerprints: []string{"haproxy"},
		Confidence:   75.0,
	},
	"f5_bigip_lb": {
		Name:         "F5 BIG-IP Load Balancer",
		Headers:      []string{"bigipserver", "server: bigip"},
		Fingerprints: []string{"f5", "bigip"},
		Confidence:   85.0,
	},
}

// LoadBalancerSignature represents a load balancer detection signature
type LoadBalancerSignature struct {
	Name         string
	Headers      []string
	Fingerprints []string
	Confidence   float64
}

// DDoSProtectionDatabase contains DDoS protection service signatures
var DDoSProtectionDatabase = map[string]DDoSProtectionSignature{
	"cloudflare_ddos": {
		Name:         "Cloudflare DDoS Protection",
		Headers:      []string{"cf-ray", "server: cloudflare"},
		BlockPages:   []string{"ddos protection by cloudflare", "checking your browser"},
		ErrorCodes:   []int{503, 520, 521, 522, 523, 524},
		Fingerprints: []string{"cloudflare", "ddos protection"},
		Confidence:   90.0,
	},
	"akamai_prolexic": {
		Name:         "Akamai Prolexic",
		Headers:      []string{"akamai-ghost-ip", "x-akamai-edgescape"},
		BlockPages:   []string{"akamai", "prolexic"},
		ErrorCodes:   []int{403, 503},
		Fingerprints: []string{"akamai", "prolexic"},
		Confidence:   85.0,
	},
	"aws_shield": {
		Name:         "AWS Shield",
		Headers:      []string{"x-amzn-requestid", "x-amzn-trace-id"},
		BlockPages:   []string{"aws", "shield"},
		ErrorCodes:   []int{503},
		Fingerprints: []string{"aws", "shield"},
		Confidence:   80.0,
	},
	"incapsula": {
		Name:         "Imperva Incapsula DDoS Protection",
		Headers:      []string{"x-iinfo", "set-cookie: incap_ses"},
		BlockPages:   []string{"incapsula", "ddos protection"},
		ErrorCodes:   []int{403, 503},
		Fingerprints: []string{"incapsula", "imperva"},
		Confidence:   85.0,
	},
}

// DDoSProtectionSignature represents a DDoS protection service signature
type DDoSProtectionSignature struct {
	Name         string
	Headers      []string
	BlockPages   []string
	ErrorCodes   []int
	Fingerprints []string
	Confidence   float64
}

// SecurityHeaderPatterns contains patterns for security header analysis
var SecurityHeaderPatterns = map[string]*regexp.Regexp{
	"strict-transport-security": regexp.MustCompile(`(?i)strict-transport-security`),
	"content-security-policy":   regexp.MustCompile(`(?i)content-security-policy`),
	"x-frame-options":           regexp.MustCompile(`(?i)x-frame-options`),
	"x-content-type-options":    regexp.MustCompile(`(?i)x-content-type-options`),
	"x-xss-protection":          regexp.MustCompile(`(?i)x-xss-protection`),
	"referrer-policy":           regexp.MustCompile(`(?i)referrer-policy`),
	"permissions-policy":        regexp.MustCompile(`(?i)permissions-policy`),
	"feature-policy":            regexp.MustCompile(`(?i)feature-policy`),
}

// GetCDNDatabase returns the CDN detection database
func GetCDNDatabase() map[string]CDNSignature {
	return CDNDatabase
}

// GetWAFDatabase returns the WAF detection database
func GetWAFDatabase() map[string]WAFSignature {
	return WAFDatabase
}

// GetLoadBalancerDatabase returns the load balancer detection database
func GetLoadBalancerDatabase() map[string]LoadBalancerSignature {
	return LoadBalancerDatabase
}

// GetDDoSProtectionDatabase returns the DDoS protection detection database
func GetDDoSProtectionDatabase() map[string]DDoSProtectionSignature {
	return DDoSProtectionDatabase
}

// GetSecurityHeaderPatterns returns the security header analysis patterns
func GetSecurityHeaderPatterns() map[string]*regexp.Regexp {
	return SecurityHeaderPatterns
}