package consolemenu

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/letgo/cracker"
	"github.com/letgo/scanner"
)

// Menu represents the console menu
type Menu struct {
	Config              *cracker.AttackConfig
	DiscoveredEndpoints []scanner.EndpointResult
	resultMutex         sync.Mutex // For thread-safe result writing
}

// New creates a new menu
func New(config *cracker.AttackConfig) *Menu {
	return &Menu{Config: config}
}

// Display shows the main menu
func (m *Menu) Display() {
	fmt.Println("===== Security Testing Menu ======")
	fmt.Println("[Scan]")
	fmt.Println("  1) Scan for Login Endpoints")
	fmt.Println("  2) Scan for Secrets/Env/Tokens")
	fmt.Println("  3) Scan Path Traversal (LFI/RFI)")
	fmt.Println("[Generate]")
	fmt.Println("  4) Generate User List")
	fmt.Println("  5) Generate Password List")
	fmt.Println("  6) Generate User Agents")
	fmt.Println("[Attack]")
	fmt.Println("  7) Attack Brute force with cURL")
	fmt.Println("  8) DDoS Attack (cURL)")
	fmt.Println("  9) Scan Target for DDoS cURLs")
	fmt.Println("[Proxy]")
	fmt.Println("  10) Scrape Proxies")
	fmt.Println("  11) Validate Proxies")
	fmt.Println("  12) Exit")
	fmt.Print("Choose an option [1-12]: ")
}

// Process handles the user's menu choice
func (m *Menu) Process() bool {
	reader := bufio.NewReader(os.Stdin)
	choice, _ := reader.ReadString('\n')
	choice = strings.TrimSpace(choice)

	switch choice {
	case "1":
		m.scanEndpoints()
	case "2":
		m.scanSecrets()
	case "3":
		m.pathTraversalAttack()
	case "4":
		m.generateUserList()
	case "5":
		m.generatePasswordList()
	case "6":
		m.generateUserAgents()
	case "7":
		m.attackWithCurl()
	case "8":
		m.ddosAttack()
	case "9":
		m.scanDDOSTarget()
	case "10":
		m.scrapeProxies()
	case "11":
		m.validateProxies()
	case "12":
		fmt.Println("Exiting...")
		return false
	default:
		fmt.Println("Invalid option. Please try again.")
	}
	return true
}
