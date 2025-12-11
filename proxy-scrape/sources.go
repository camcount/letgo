package proxy

// proxy source list
type proxySource struct {
	URL      string
	Protocol string
	Format   string
}

func proxySources() []proxySource {
	return []proxySource{
		{"https://api.proxyscrape.com/v2/?request=get&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all", "http", "text"},
		{"https://api.proxyscrape.com/v2/?request=get&protocol=socks4&timeout=10000&country=all", "socks4", "text"},
		{"https://api.proxyscrape.com/v2/?request=get&protocol=socks5&timeout=10000&country=all", "socks5", "text"},
		{"https://www.proxy-list.download/api/v1/get?type=http", "http", "text"},
		{"https://www.proxy-list.download/api/v1/get?type=socks4", "socks4", "text"},
		{"https://www.proxy-list.download/api/v1/get?type=socks5", "socks5", "text"},
		{"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt", "http", "text"},
		{"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt", "socks4", "text"},
		{"https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", "socks5", "text"},
		{"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt", "http", "text"},
		{"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt", "https", "text"},
		{"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt", "socks4", "text"},
		{"https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt", "socks5", "text"},
		{"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt", "http", "text"},
		{"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks4.txt", "socks4", "text"},
		{"https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt", "socks5", "text"},
		{"https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt", "socks5", "text"},
		{"https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt", "socks4", "text"},
		{"https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt", "http", "text"},
		{"https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/SOCKS4_RAW.txt", "socks4", "text"},
		{"https://raw.githubusercontent.com/roosterkid/openproxylist/refs/heads/main/SOCKS5_RAW.txt", "socks5", "text"},
	}
}
