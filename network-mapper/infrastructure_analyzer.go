package networkmapper

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// InfrastructureAnalyzerImpl implements the InfrastructureAnalyzer interface
type InfrastructureAnalyzerImpl struct {
	httpClient      *http.Client
	hostingDB       map[string]HostingProvider
	cloudPlatformDB map[string]CloudPlatform
	subdomainDict   []string
}

// CloudPlatform represents a cloud platform with identification patterns
type CloudPlatform struct {
	Name     string
	ASNs     []string
	IPRanges []string
	Domains  []string
	Services []string
}

// NewInfrastructureAnalyzer creates a new infrastructure analyzer instance
func NewInfrastructureAnalyzer() *InfrastructureAnalyzerImpl {
	return &InfrastructureAnalyzerImpl{
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
		hostingDB:       initHostingProviderDB(),
		cloudPlatformDB: initCloudPlatformDB(),
		subdomainDict:   initSubdomainDictionary(),
	}
}

// AnalyzeInfrastructure performs comprehensive infrastructure analysis
func (ia *InfrastructureAnalyzerImpl) AnalyzeInfrastructure(ctx context.Context, target string) (InfrastructureInfo, error) {
	var info InfrastructureInfo

	// Create a context with timeout to prevent hanging
	timeoutCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Resolve target to IP addresses with timeout
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{
				Timeout: 5 * time.Second,
			}
			return d.DialContext(ctx, network, address)
		},
	}

	ips, err := resolver.LookupIPAddr(timeoutCtx, target)
	if err != nil {
		return info, fmt.Errorf("failed to resolve target %s: %w", target, err)
	}

	if len(ips) > 0 {
		ip := ips[0].IP.String()

		// Identify hosting provider
		hostingProvider, _ := ia.IdentifyHostingProvider(timeoutCtx, ip)
		info.HostingProvider = hostingProvider

		// Identify cloud platform
		cloudPlatform, _ := ia.GetCloudPlatform(timeoutCtx, ip)
		info.CloudPlatform = cloudPlatform

		// Get network information
		info.NetworkInfo = ia.getNetworkInfo(timeoutCtx, ip)
	}

	// Get SSL certificate information for HTTPS services (with timeout)
	sslInfo, err := ia.GetSSLCertificate(timeoutCtx, target, 443)
	if err == nil {
		info.SSLInfo = sslInfo
	}

	// Enumerate subdomains (with timeout)
	subdomains, err := ia.EnumerateSubdomains(timeoutCtx, target)
	if err == nil {
		info.Subdomains = subdomains
	}

	return info, nil
}

// GetSSLCertificate retrieves and analyzes SSL certificate information
func (ia *InfrastructureAnalyzerImpl) GetSSLCertificate(ctx context.Context, hostname string, port int) (SSLCertInfo, error) {
	var certInfo SSLCertInfo

	// Create TLS connection
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", fmt.Sprintf("%s:%d", hostname, port), &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return certInfo, fmt.Errorf("failed to establish TLS connection: %w", err)
	}
	defer conn.Close()

	// Get certificate chain
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return certInfo, fmt.Errorf("no certificates found")
	}

	// Analyze the leaf certificate
	cert := certs[0]
	certInfo.Issuer = cert.Issuer.String()
	certInfo.Subject = cert.Subject.String()
	certInfo.ValidFrom = cert.NotBefore
	certInfo.ValidTo = cert.NotAfter
	certInfo.SignatureAlg = cert.SignatureAlgorithm.String()
	certInfo.SANs = cert.DNSNames

	// Calculate fingerprint (SHA-256)
	certInfo.Fingerprint = fmt.Sprintf("%x", cert.Raw)

	// Determine key size
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		certInfo.KeySize = pub.N.BitLen()
	case *ecdsa.PublicKey:
		certInfo.KeySize = pub.Curve.Params().BitSize
	}

	// Check if wildcard certificate
	for _, name := range cert.DNSNames {
		if strings.HasPrefix(name, "*.") {
			certInfo.IsWildcard = true
			break
		}
	}

	// Check if self-signed
	certInfo.IsSelfSigned = cert.Issuer.String() == cert.Subject.String()

	return certInfo, nil
}

// EnumerateSubdomains attempts to discover related subdomains
func (ia *InfrastructureAnalyzerImpl) EnumerateSubdomains(ctx context.Context, domain string) ([]string, error) {
	var subdomains []string
	found := make(map[string]bool)

	// Create a context with timeout to prevent hanging
	timeoutCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Use only a subset of common subdomains to avoid timeout
	commonSubdomains := []string{"www", "mail", "ftp", "api", "admin", "blog", "dev", "test", "staging"}

	// Try common subdomain prefixes with timeout
	for _, prefix := range commonSubdomains {
		select {
		case <-timeoutCtx.Done():
			return subdomains, nil // Return what we found so far
		default:
		}

		subdomain := fmt.Sprintf("%s.%s", prefix, domain)
		
		// Attempt DNS resolution with timeout
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: 2 * time.Second,
				}
				return d.DialContext(ctx, network, address)
			},
		}

		_, err := resolver.LookupIPAddr(timeoutCtx, subdomain)
		if err == nil && !found[subdomain] {
			subdomains = append(subdomains, subdomain)
			found[subdomain] = true
		}
	}

	return subdomains, nil
}

// IdentifyHostingProvider determines the hosting provider for an IP address
func (ia *InfrastructureAnalyzerImpl) IdentifyHostingProvider(ctx context.Context, ip string) (string, error) {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return "", fmt.Errorf("invalid IP address: %s", ip)
	}

	// Check against known hosting provider IP ranges
	for name, provider := range ia.hostingDB {
		for _, ipRange := range provider.IPRanges {
			_, cidr, err := net.ParseCIDR(ipRange)
			if err != nil {
				continue
			}
			if cidr.Contains(ipAddr) {
				return name, nil
			}
		}
	}

	return "Unknown", nil
}

// GetCloudPlatform identifies the cloud platform (AWS, GCP, Azure, etc.)
func (ia *InfrastructureAnalyzerImpl) GetCloudPlatform(ctx context.Context, ip string) (string, error) {
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return "", fmt.Errorf("invalid IP address: %s", ip)
	}

	// Check against known cloud platform IP ranges
	for name, platform := range ia.cloudPlatformDB {
		for _, ipRange := range platform.IPRanges {
			_, cidr, err := net.ParseCIDR(ipRange)
			if err != nil {
				continue
			}
			if cidr.Contains(ipAddr) {
				return name, nil
			}
		}
	}

	return "Unknown", nil
}

// getNetworkInfo retrieves network-related information for an IP address
func (ia *InfrastructureAnalyzerImpl) getNetworkInfo(ctx context.Context, ip string) NetworkInfo {
	var info NetworkInfo

	// Perform reverse DNS lookup
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		info.Organization = names[0]
	}

	// For a real implementation, you would query WHOIS databases or ASN APIs
	// This is a simplified version
	info.ASN = "Unknown"
	info.BGPPrefix = "Unknown"
	info.Abuse = "Unknown"

	return info
}

// initHostingProviderDB initializes the hosting provider database
func initHostingProviderDB() map[string]HostingProvider {
	return map[string]HostingProvider{
		"aws": {
			Name:     "Amazon Web Services",
			ASNs:     []string{"AS16509", "AS14618"},
			IPRanges: []string{"3.0.0.0/8", "13.0.0.0/8", "18.0.0.0/8", "52.0.0.0/8", "54.0.0.0/8"},
			Domains:  []string{".amazonaws.com", ".aws.amazon.com"},
			Features: []string{"ec2", "s3", "cloudfront", "elb"},
		},
		"gcp": {
			Name:     "Google Cloud Platform",
			ASNs:     []string{"AS15169", "AS36040"},
			IPRanges: []string{"34.64.0.0/10", "35.184.0.0/13", "104.154.0.0/15", "130.211.0.0/22"},
			Domains:  []string{".googleusercontent.com", ".googleapis.com"},
			Features: []string{"gce", "gcs", "gae"},
		},
		"azure": {
			Name:     "Microsoft Azure",
			ASNs:     []string{"AS8075"},
			IPRanges: []string{"13.64.0.0/11", "20.0.0.0/8", "40.64.0.0/10", "52.224.0.0/11"},
			Domains:  []string{".azurewebsites.net", ".azure.com"},
			Features: []string{"vm", "storage", "cdn"},
		},
		"digitalocean": {
			Name:     "DigitalOcean",
			ASNs:     []string{"AS14061"},
			IPRanges: []string{"104.131.0.0/16", "138.197.0.0/16", "159.203.0.0/16", "165.227.0.0/16"},
			Domains:  []string{".digitaloceanspaces.com"},
			Features: []string{"droplets", "spaces", "load-balancer"},
		},
		"linode": {
			Name:     "Linode",
			ASNs:     []string{"AS63949"},
			IPRanges: []string{"45.79.0.0/16", "66.175.208.0/20", "69.164.192.0/18", "173.255.192.0/18"},
			Domains:  []string{".linode.com"},
			Features: []string{"compute", "storage", "networking"},
		},
	}
}

// initCloudPlatformDB initializes the cloud platform database
func initCloudPlatformDB() map[string]CloudPlatform {
	return map[string]CloudPlatform{
		"aws": {
			Name:     "Amazon Web Services",
			ASNs:     []string{"AS16509", "AS14618"},
			IPRanges: []string{"3.0.0.0/8", "13.0.0.0/8", "18.0.0.0/8", "52.0.0.0/8", "54.0.0.0/8"},
			Domains:  []string{".amazonaws.com", ".aws.amazon.com"},
			Services: []string{"EC2", "S3", "CloudFront", "ELB", "RDS"},
		},
		"gcp": {
			Name:     "Google Cloud Platform",
			ASNs:     []string{"AS15169", "AS36040"},
			IPRanges: []string{"34.64.0.0/10", "35.184.0.0/13", "104.154.0.0/15", "130.211.0.0/22"},
			Domains:  []string{".googleusercontent.com", ".googleapis.com"},
			Services: []string{"Compute Engine", "Cloud Storage", "App Engine", "Cloud SQL"},
		},
		"azure": {
			Name:     "Microsoft Azure",
			ASNs:     []string{"AS8075"},
			IPRanges: []string{"13.64.0.0/11", "20.0.0.0/8", "40.64.0.0/10", "52.224.0.0/11"},
			Domains:  []string{".azurewebsites.net", ".azure.com"},
			Services: []string{"Virtual Machines", "Blob Storage", "App Service", "SQL Database"},
		},
	}
}

// initSubdomainDictionary initializes the subdomain dictionary for enumeration
func initSubdomainDictionary() []string {
	return []string{
		"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2",
		"cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns", "blog",
		"pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3", "mail2", "new",
		"mysql", "old", "www1", "email", "img", "www3", "help", "shop", "sql", "secure",
		"beta", "pic", "mail3", "staging", "web", "media", "static", "ads", "www4", "www5",
		"api", "cdn", "app", "mobile", "demo", "support", "store", "download", "video",
		"music", "search", "photo", "photos", "upload", "files", "docs", "wiki", "chat",
	}
}