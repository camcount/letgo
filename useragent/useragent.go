package useragent

import (
	"fmt"
	"math/rand"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// SelectionStrategy defines how user agents are selected
type SelectionStrategy string

const (
	StrategyRandom      SelectionStrategy = "random"
	StrategyRotating    SelectionStrategy = "rotating"
	StrategyWeighted    SelectionStrategy = "weighted"
	StrategyNoDuplicate SelectionStrategy = "no-duplicate"
)

// UserAgentConfig holds configuration for user agent generation
type UserAgentConfig struct {
	Strategy SelectionStrategy
	Seed     int64
}

// UserAgentGenerator generates and manages user agents
type UserAgentGenerator struct {
	agents          []string
	strategy        SelectionStrategy
	rand            *rand.Rand
	rotationCounter atomic.Uint64
	mu              sync.RWMutex
}

// Desktop user agents
var desktopAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/131.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/130.0.0.0",
}

// Mobile user agents
var mobileAgents = []string{
	"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPad; CPU OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/132.0 Mobile",
	"Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Samsung Internet/24.0 Chrome/131.0.0.0 Mobile Safari/537.36",
}

// Bot/Crawler user agents
var botAgents = []string{
	"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
	"curl/7.68.0",
	"Wget/1.20.3",
	"Python-Requests/2.28.2",
}

// New creates a new UserAgentGenerator with the given configuration
func New(config UserAgentConfig) *UserAgentGenerator {
	if config.Strategy == "" {
		config.Strategy = StrategyRandom
	}

	generator := &UserAgentGenerator{
		strategy: config.Strategy,
	}

	// Combine all agents
	generator.agents = append(generator.agents, desktopAgents...)
	generator.agents = append(generator.agents, mobileAgents...)
	generator.agents = append(generator.agents, botAgents...)

	// Initialize random source
	if config.Seed == 0 {
		generator.rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	} else {
		generator.rand = rand.New(rand.NewSource(config.Seed))
	}

	return generator
}

// GetRandom returns a random user agent
func (u *UserAgentGenerator) GetRandom() string {
	u.mu.RLock()
	defer u.mu.RUnlock()

	if len(u.agents) == 0 {
		return ""
	}

	return u.agents[u.rand.Intn(len(u.agents))]
}

// GetRotating returns the next user agent in rotation sequence (thread-safe)
func (u *UserAgentGenerator) GetRotating() string {
	if len(u.agents) == 0 {
		return ""
	}

	counter := u.rotationCounter.Add(1) - 1
	return u.agents[counter%uint64(len(u.agents))]
}

// GenerateByQuantity generates the specified number of user agents
func (u *UserAgentGenerator) GenerateByQuantity(count int) []string {
	if count <= 0 {
		return []string{}
	}

	u.mu.RLock()
	defer u.mu.RUnlock()

	result := make([]string, 0, count)

	switch u.strategy {
	case StrategyRotating:
		// Cycle through agents in order
		for i := 0; i < count; i++ {
			result = append(result, u.agents[i%len(u.agents)])
		}
	case StrategyWeighted:
		// Weighted selection with repetition - favors variety
		seen := make(map[string]bool)
		for i := 0; i < count; i++ {
			agent := u.agents[u.rand.Intn(len(u.agents))]
			if !seen[agent] && len(seen) < len(u.agents) {
				seen[agent] = true
				result = append(result, agent)
			} else if len(seen) == len(u.agents) {
				// If all agents have been selected, add random ones
				result = append(result, u.agents[u.rand.Intn(len(u.agents))])
			}
		}
	case StrategyNoDuplicate:
		// Shuffle agents and cycle through without duplicates
		agents := make([]string, len(u.agents))
		copy(agents, u.agents)

		for i := 0; i < count; i++ {
			if i%len(agents) == 0 && i > 0 {
				// Reshuffle after cycling through all agents
				u.shuffleSlice(agents)
			}
			result = append(result, agents[i%len(agents)])
		}
	default: // StrategyRandom
		// Pure random selection with possible repetition
		for i := 0; i < count; i++ {
			result = append(result, u.agents[u.rand.Intn(len(u.agents))])
		}
	}

	return result
}

// shuffleSlice shuffles a slice in place using Fisher-Yates algorithm
func (u *UserAgentGenerator) shuffleSlice(slice []string) {
	for i := len(slice) - 1; i > 0; i-- {
		j := u.rand.Intn(i + 1)
		slice[i], slice[j] = slice[j], slice[i]
	}
}

// GenerateToFile generates user agents and writes them to a file
func (u *UserAgentGenerator) GenerateToFile(filename string, count int) error {
	agents := u.GenerateByQuantity(count)

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	for _, agent := range agents {
		if _, err := file.WriteString(agent + "\n"); err != nil {
			return fmt.Errorf("failed to write to file: %w", err)
		}
	}

	return nil
}

// GetAgentCount returns total number of available agents
func (u *UserAgentGenerator) GetAgentCount() int {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return len(u.agents)
}

// GetDesktopAgents returns all available desktop user agents
func (u *UserAgentGenerator) GetDesktopAgents() []string {
	return append([]string{}, desktopAgents...)
}

// GetMobileAgents returns all available mobile user agents
func (u *UserAgentGenerator) GetMobileAgents() []string {
	return append([]string{}, mobileAgents...)
}

// GetBotAgents returns all available bot/crawler user agents
func (u *UserAgentGenerator) GetBotAgents() []string {
	return append([]string{}, botAgents...)
}

// GenerateUserAgents generates random user agents and writes to user-agent.txt
// If the file exists, it will be overwritten
// Uses NoDuplicate strategy to ensure no repeated agents
func (u *UserAgentGenerator) GenerateUserAgents(count int) error {
	// Use no-duplicate strategy for generation
	tempStrategy := u.strategy
	u.strategy = StrategyNoDuplicate

	agents := u.GenerateByQuantity(count)

	// Restore original strategy
	u.strategy = tempStrategy

	// Create/overwrite user-agent.txt file
	file, err := os.Create("user-agent.txt")
	if err != nil {
		return fmt.Errorf("failed to create user-agent.txt: %w", err)
	}
	defer file.Close()

	for _, agent := range agents {
		if _, err := file.WriteString(agent + "\n"); err != nil {
			return fmt.Errorf("failed to write to user-agent.txt: %w", err)
		}
	}

	return nil
}
