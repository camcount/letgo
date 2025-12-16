package consolemenu

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/letgo/cracker"
	"github.com/letgo/paths"
	"github.com/letgo/scanner"
)

var dataDir = paths.GetDataDir()

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
	fmt.Println("  4) Scan Target for DDoS cURLs")
	fmt.Println("  5) Network Mapper (NMAP-like)")
	fmt.Println("[Generate]")
	fmt.Println("  6) Generate User List")
	fmt.Println("  7) Generate Password List")
	fmt.Println("  8) Generate User Agents")
	fmt.Println("[Attack]")
	fmt.Println("  9) Attack Brute force with cURL")
	fmt.Println("  10) DDoS Attack (cURL)")
	fmt.Println("[Proxy]")
	fmt.Println("  11) Scrape Proxies")
	fmt.Println("  12) Validate Proxies")
	fmt.Println("  13) Exit")
	fmt.Print("Choose an option [1-13]: ")
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
		m.scanDDOSTarget()
	case "5":
		m.networkMapper()
	case "6":
		m.generateUserList()
	case "7":
		m.generatePasswordList()
	case "8":
		m.generateUserAgents()
	case "9":
		m.attackWithCurl()
	case "10":
		m.ddosAttack()
	case "11":
		m.scrapeProxies()
	case "12":
		m.validateProxies()
	case "13":
		fmt.Println("Exiting...")
		return false
	default:
		fmt.Println("Invalid option. Please try again.")
	}
	return true
}
