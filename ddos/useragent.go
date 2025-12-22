package ddos

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/letgo/paths"
)

// getBuiltInUserAgents returns the default built-in user agents
func getBuiltInUserAgents() []string {
	return []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36",
	}
}

// loadUserAgentsFromFile loads user agents from a file (one per line)
// Optimized for performance: deduplicates entries and pre-allocates capacity
func loadUserAgentsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open user agent file: %w", err)
	}
	defer file.Close()

	// Use map for deduplication (many user-agent.txt files have duplicates)
	seen := make(map[string]bool)
	// Pre-allocate with reasonable capacity (most files have 100-300 entries)
	agents := make([]string, 0, 200)

	scanner := bufio.NewScanner(file)
	// Increase buffer size for better I/O performance on large files
	buf := make([]byte, 0, 64*1024) // 64KB buffer
	scanner.Buffer(buf, 1024*1024)  // Max 1MB line length

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line != "" && !strings.HasPrefix(line, "#") {
			// Deduplicate: only add if not seen before
			if !seen[line] {
				seen[line] = true
				agents = append(agents, line)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading user agent file: %w", err)
	}

	if len(agents) == 0 {
		return nil, fmt.Errorf("no user agents found in file")
	}

	// Trim to actual size to save memory
	if cap(agents) > len(agents)*2 {
		trimmed := make([]string, len(agents))
		copy(trimmed, agents)
		return trimmed, nil
	}

	return agents, nil
}

// loadUserAgentsFromDefaultFile loads user agents from the default user-agent.txt file
// It looks for the file in application/data/user-agent.txt
func loadUserAgentsFromDefaultFile() ([]string, error) {
	dataDir := paths.GetDataDir()
	userAgentFilePath := filepath.Join(dataDir, "user-agent.txt")

	// Verify file exists before attempting to load
	if _, err := os.Stat(userAgentFilePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("user agent file not found at: %s", userAgentFilePath)
	}

	return loadUserAgentsFromFile(userAgentFilePath)
}
