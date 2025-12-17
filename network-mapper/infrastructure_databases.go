package networkmapper

// HostingProviderDatabase contains comprehensive hosting provider signatures
var HostingProviderDatabase = map[string]HostingProvider{
	"aws": {
		Name:     "Amazon Web Services",
		ASNs:     []string{"AS16509", "AS14618", "AS8987", "AS62785"},
		IPRanges: []string{"3.0.0.0/8", "13.0.0.0/8", "18.0.0.0/8", "52.0.0.0/8", "54.0.0.0/8", "99.0.0.0/8", "205.251.192.0/19", "216.137.32.0/19"},
		Domains:  []string{".amazonaws.com", ".aws.amazon.com", ".awsglobalconfig.com"},
		Features: []string{"ec2", "s3", "cloudfront", "elb", "rds", "lambda", "apigateway"},
	},
	"gcp": {
		Name:     "Google Cloud Platform",
		ASNs:     []string{"AS15169", "AS36040", "AS36492", "AS139070"},
		IPRanges: []string{"34.64.0.0/10", "35.184.0.0/13", "35.192.0.0/14", "35.196.0.0/15", "35.198.0.0/16", "35.199.0.0/17", "35.200.0.0/13", "35.208.0.0/12", "35.224.0.0/12", "35.240.0.0/13"},
		Domains:  []string{".googleusercontent.com", ".googleapis.com", ".gcp.goog", ".google.com"},
		Features: []string{"gce", "gcs", "gae", "gke", "cloud-sql", "cloud-functions"},
	},
	"azure": {
		Name:     "Microsoft Azure",
		ASNs:     []string{"AS8075", "AS8068", "AS12076"},
		IPRanges: []string{"13.64.0.0/11", "20.0.0.0/8", "40.64.0.0/10", "52.96.0.0/12", "104.40.0.0/13", "137.116.0.0/14", "168.61.0.0/16", "191.232.0.0/13"},
		Domains:  []string{".azurewebsites.net", ".azure.com", ".azureedge.net", ".vo.msecnd.net"},
		Features: []string{"vm", "storage", "cdn", "sql-database", "functions", "app-service"},
	},
	"digitalocean": {
		Name:     "DigitalOcean",
		ASNs:     []string{"AS14061", "AS393406"},
		IPRanges: []string{"104.131.0.0/16", "138.197.0.0/16", "159.203.0.0/16", "159.89.0.0/16", "162.243.0.0/16", "167.99.0.0/16", "178.62.0.0/16", "188.166.0.0/16", "206.189.0.0/16", "209.97.128.0/18"},
		Domains:  []string{".digitaloceanspaces.com", ".ondigitalocean.app"},
		Features: []string{"droplets", "spaces", "kubernetes", "databases", "functions"},
	},
	"linode": {
		Name:     "Linode",
		ASNs:     []string{"AS63949"},
		IPRanges: []string{"45.33.0.0/16", "45.56.0.0/16", "45.79.0.0/16", "66.175.208.0/20", "69.164.192.0/18", "74.207.224.0/19", "96.126.96.0/19", "139.144.0.0/16", "172.104.0.0/15", "173.255.192.0/18", "192.46.208.0/20", "198.58.96.0/19", "198.74.48.0/20", "23.239.0.0/16", "50.116.0.0/16"},
		Domains:  []string{".linode.com", ".linodeobjects.com"},
		Features: []string{"linodes", "object-storage", "kubernetes", "databases"},
	},
	"vultr": {
		Name:     "Vultr",
		ASNs:     []string{"AS20473"},
		IPRanges: []string{"45.32.0.0/16", "45.63.0.0/16", "45.76.0.0/16", "45.77.0.0/16", "104.156.224.0/19", "108.61.0.0/16", "140.82.0.0/16", "149.28.0.0/16", "155.138.0.0/16", "207.148.0.0/16", "208.167.224.0/19"},
		Domains:  []string{".vultr.com", ".vultrusercontent.com"},
		Features: []string{"instances", "object-storage", "kubernetes", "databases"},
	},
	"ovh": {
		Name:     "OVH",
		ASNs:     []string{"AS16276", "AS35540"},
		IPRanges: []string{"5.196.0.0/16", "37.59.0.0/16", "46.105.0.0/16", "51.15.0.0/16", "51.68.0.0/16", "51.75.0.0/16", "51.77.0.0/16", "51.79.0.0/16", "51.83.0.0/16", "51.89.0.0/16", "54.36.0.0/16", "87.98.128.0/17", "91.121.0.0/16", "94.23.0.0/16", "135.125.0.0/16", "137.74.0.0/16", "141.94.0.0/16", "141.95.0.0/16", "145.239.0.0/16", "146.59.0.0/16", "147.135.0.0/16", "151.80.0.0/16", "152.228.128.0/17", "164.132.0.0/16", "176.31.0.0/16", "178.32.0.0/15", "188.165.0.0/16", "193.70.0.0/17", "195.154.0.0/16", "198.27.64.0/18", "213.186.32.0/19", "213.251.128.0/18"},
		Domains:  []string{".ovh.net", ".ovhcloud.com"},
		Features: []string{"instances", "object-storage", "kubernetes", "databases"},
	},
	"hetzner": {
		Name:     "Hetzner",
		ASNs:     []string{"AS24940"},
		IPRanges: []string{"5.9.0.0/16", "46.4.0.0/16", "78.46.0.0/15", "88.99.0.0/16", "94.130.0.0/16", "116.203.0.0/16", "135.181.0.0/16", "136.243.0.0/16", "138.201.0.0/16", "139.59.0.0/16", "144.76.0.0/16", "148.251.0.0/16", "159.69.0.0/16", "162.55.0.0/16", "168.119.0.0/16", "176.9.0.0/16", "178.63.0.0/16", "188.40.0.0/16", "195.201.0.0/16", "213.133.96.0/19", "213.239.192.0/18"},
		Domains:  []string{".hetzner.com", ".hetzner.de"},
		Features: []string{"cloud", "dedicated", "storage"},
	},
	"cloudflare": {
		Name:     "Cloudflare",
		ASNs:     []string{"AS13335"},
		IPRanges: []string{"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"},
		Domains:  []string{".cloudflare.com", ".cloudflare.net", ".workers.dev"},
		Features: []string{"cdn", "dns", "workers", "pages", "r2"},
	},
	"fastly": {
		Name:     "Fastly",
		ASNs:     []string{"AS54113"},
		IPRanges: []string{"23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24", "103.245.222.0/23", "103.245.224.0/24", "104.156.80.0/20", "146.75.0.0/16", "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17", "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20", "172.111.64.0/18", "185.31.16.0/22", "199.27.72.0/21", "199.232.0.0/16"},
		Domains:  []string{".fastly.com", ".fastlylb.net"},
		Features: []string{"cdn", "edge-compute", "security"},
	},
}

// ASNInfoDatabase contains ASN to organization mappings
var ASNInfoDatabase = map[string]ASNInfoRecord{
	"AS13335": {
		Number:       "AS13335",
		Name:         "CLOUDFLARENET",
		Organization: "Cloudflare, Inc.",
		Country:      "US",
		Registry:     "ARIN",
	},
	"AS16509": {
		Number:       "AS16509",
		Organization: "Amazon.com, Inc.",
		Country:      "US",
		Registry:     "ARIN",
	},
	"AS15169": {
		Number:       "AS15169",
		Organization: "Google LLC",
		Country:      "US",
		Registry:     "ARIN",
	},
	"AS8075": {
		Number:       "AS8075",
		Organization: "Microsoft Corporation",
		Country:      "US",
		Registry:     "ARIN",
	},
	"AS14061": {
		Number:       "AS14061",
		Organization: "DigitalOcean, LLC",
		Country:      "US",
		Registry:     "ARIN",
	},
	"AS63949": {
		Number:       "AS63949",
		Organization: "Linode, LLC",
		Country:      "US",
		Registry:     "ARIN",
	},
	"AS20473": {
		Number:       "AS20473",
		Organization: "The Constant Company, LLC",
		Country:      "US",
		Registry:     "ARIN",
	},
	"AS16276": {
		Number:       "AS16276",
		Organization: "OVH SAS",
		Country:      "FR",
		Registry:     "RIPE",
	},
	"AS24940": {
		Number:       "AS24940",
		Organization: "Hetzner Online GmbH",
		Country:      "DE",
		Registry:     "RIPE",
	},
	"AS54113": {
		Number:       "AS54113",
		Organization: "Fastly",
		Country:      "US",
		Registry:     "ARIN",
	},
}

// ASNInfoRecord represents ASN information record
type ASNInfoRecord struct {
	Number       string
	Name         string
	Organization string
	Country      string
	Registry     string
}

// GetHostingProviderDatabase returns the hosting provider database
func GetHostingProviderDatabase() map[string]HostingProvider {
	return HostingProviderDatabase
}

// GetASNInfoDatabase returns the ASN database
func GetASNInfoDatabase() map[string]ASNInfoRecord {
	return ASNInfoDatabase
}

// LookupHostingProvider attempts to identify hosting provider by ASN or IP range
func LookupHostingProvider(asn string, ip string) *HostingProvider {
	for _, provider := range HostingProviderDatabase {
		// Check ASN match
		for _, providerASN := range provider.ASNs {
			if providerASN == asn {
				return &provider
			}
		}
		
		// TODO: Add IP range matching logic if needed
	}
	return nil
}

// LookupASNInfo looks up ASN information
func LookupASNInfo(asn string) *ASNInfoRecord {
	if info, exists := ASNInfoDatabase[asn]; exists {
		return &info
	}
	return nil
}