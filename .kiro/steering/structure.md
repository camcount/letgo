# Project Structure

## Root Layout

```
letgo/
├── cmd/letgo/           # Main application entry point
├── application/         # Built executables and runtime data
├── console-menu/        # Interactive CLI menu system
├── cracker/            # Password cracking functionality
├── ddos/               # DDoS attack implementations
├── ddos-scanner/       # DDoS target scanning
├── scanner/            # General vulnerability scanning
├── secretscanner/      # Secret/token detection
├── pathtraversal/      # Path traversal attack detection
├── proxy-scrape/       # Proxy collection and management
├── paths/              # Path utilities and data directory management
├── useragent/          # User agent management
├── userlist/           # Username list generation
├── wordlist/           # Password list generation
└── curlparser/         # cURL command parsing
```

## Key Directories

### `/cmd/letgo/`

- **Purpose**: Application entry point following Go conventions
- **Files**: `main.go` - initializes data directories and starts menu

### `/application/`

- **Purpose**: Runtime directory for executables and data
- **Structure**:
  ```
  application/
  ├── letgo.exe           # Windows executable
  ├── letgo               # Unix executable
  ├── letgo-amd64         # Linux AMD64 executable
  └── data/               # Runtime data directory
      ├── *.txt           # Configuration and wordlist files
      ├── proxy/          # Proxy lists and configurations
      ├── ddos-targets/   # DDoS target configurations
      └── ddos-templates/ # Attack template files
  ```

### Core Modules

#### `/console-menu/`

- Interactive CLI interface
- Menu routing and user input handling
- Orchestrates calls to other modules

#### `/ddos/`

- Multiple attack mode implementations
- Configuration parsing from templates
- Real-time statistics and progress tracking
- Files: `attack.go`, `flood.go`, `http2.go`, `slowloris.go`, `rudy.go`, `tls.go`

#### `/cracker/`

- HTTP/HTTPS login brute forcing
- Multi-user attack support
- cURL configuration import

#### Scanning Modules

- `/scanner/` - General endpoint discovery
- `/secretscanner/` - Secret/token detection
- `/ddos-scanner/` - DDoS target analysis
- `/pathtraversal/` - LFI/RFI vulnerability detection

#### Utility Modules

- `/proxy-scrape/` - Proxy collection and validation
- `/paths/` - Cross-platform path management
- `/curlparser/` - cURL command parsing and conversion

## File Naming Conventions

### Go Files

- **Descriptive names**: `attack.go`, `scanner.go`, `types.go`
- **Feature-specific**: `slowloris.go`, `http2.go`, `validator.go`
- **Utility files**: `utils.go`, `types.go` (common across modules)

### Data Files (in `/application/data/`)

- **Input files**: `users.txt`, `passwords.txt`, `proxy.txt`
- **Configuration**: `cURL-Bruteforce.txt`, `cURL-DDOS.txt`
- **Templates**: `base-ddos-template.txt`, `*.txt` in `ddos-templates/`
- **Output**: `results.txt`, `valid-url.txt`

## Module Dependencies

### Import Pattern

```go
import (
    "github.com/letgo/console-menu"
    "github.com/letgo/cracker"
    "github.com/letgo/ddos"
    "github.com/letgo/paths"
)
```

### Data Directory Management

- All modules use `paths.GetDataDir()` for consistent data location
- Automatic creation of required files and directories on startup
- Cross-platform path handling

## Configuration Files

### Templates

- Located in `application/data/ddos-templates/`
- Key-value format with comments
- Base template auto-generated with all options documented

### Runtime Data

- User-editable `.txt` files for wordlists and configurations
- Results automatically written to designated output files
- Proxy lists maintained in `proxy/` subdirectory
