package consolemenu

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/letgo/useragent"
	"github.com/letgo/userlist"
	"github.com/letgo/wordlist"
)

// generateUserList generates a user list file
func (m *Menu) generateUserList() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter filename for user list (e.g., users.txt): ")
	filename, _ := reader.ReadString('\n')
	filename = strings.TrimSpace(filename)

	fmt.Print("Enter amount to generate (0 for all, default: 0): ")
	countStr, _ := reader.ReadString('\n')
	countStr = strings.TrimSpace(countStr)
	count := 0
	if countStr != "" {
		if c, err := strconv.Atoi(countStr); err == nil && c > 0 {
			count = c
		}
	}

	// Join filename with data directory
	filePath := filepath.Join(dataDir, filename)
	
	if err := userlist.Generate(filePath, count); err != nil {
		fmt.Printf("Error generating user list: %v\n", err)
		return
	}
	if count > 0 {
		fmt.Printf("User list with %d entries generated and saved to %s\n", count, filePath)
	} else {
		fmt.Printf("User list generated and saved to %s\n", filePath)
	}
}

// generatePasswordList generates a password list file
func (m *Menu) generatePasswordList() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter filename for password list (e.g., passwords.txt): ")
	filename, _ := reader.ReadString('\n')
	filename = strings.TrimSpace(filename)

	fmt.Print("Enter amount to generate (0 for all, default: 0): ")
	countStr, _ := reader.ReadString('\n')
	countStr = strings.TrimSpace(countStr)
	count := 0
	if countStr != "" {
		if c, err := strconv.Atoi(countStr); err == nil && c > 0 {
			count = c
		}
	}

	// Join filename with data directory
	filePath := filepath.Join(dataDir, filename)
	
	if err := wordlist.Generate(filePath, count); err != nil {
		fmt.Printf("Error generating password list: %v\n", err)
		return
	}
	if count > 0 {
		fmt.Printf("Password list with %d entries generated and saved to %s\n", count, filePath)
	} else {
		fmt.Printf("Password list generated and saved to %s\n", filePath)
	}
}

// generateUserAgents generates user agents and saves to user-agent.txt
func (m *Menu) generateUserAgents() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter amount to generate (default: 100): ")
	countStr, _ := reader.ReadString('\n')
	countStr = strings.TrimSpace(countStr)
	count := 100
	if countStr != "" {
		if c, err := strconv.Atoi(countStr); err == nil && c > 0 {
			count = c
		}
	}

	// Create generator with random strategy
	config := useragent.UserAgentConfig{
		Strategy: useragent.StrategyRandom,
	}
	generator := useragent.New(config)

	// Generate and write to user-agent.txt
	if err := generator.GenerateUserAgents(count); err != nil {
		fmt.Printf("Error generating user agents: %v\n", err)
		return
	}
	fmt.Printf("User agents with %d entries generated and saved to user-agent.txt\n", count)
}
