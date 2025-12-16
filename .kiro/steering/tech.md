# Technology Stack

## Language & Runtime

- **Go 1.24+** - Primary language with toolchain go1.24.11
- Cross-platform support (Windows, Linux, macOS)

## Dependencies

- `golang.org/x/crypto` - Cryptographic operations and SSH support
- `golang.org/x/net` - Advanced networking capabilities

## Build System

### Quick Build Commands

```bash
# Build for current platform
go build -o application/letgo cmd/letgo/main.go

# Cross-platform builds
GOOS=linux GOARCH=amd64 go build -o application/letgo-amd64 cmd/letgo/main.go
GOOS=windows GOARCH=amd64 go build -o application/letgo.exe cmd/letgo/main.go
GOOS=darwin GOARCH=amd64 go build -o application/letgo-darwin cmd/letgo/main.go
```

### Build Scripts

- `build.bat` - Windows batch script with interactive menu
- `build.ps1` - PowerShell script with colored output and error handling
- Both scripts support building all platforms and running executables

### Windows PowerShell Cross-compilation

```powershell
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -o application/letgo-amd64 cmd/letgo/main.go
```

## Architecture Patterns

### Module Organization

- **Modular design** - Each feature in separate package (ddos, cracker, scanner, etc.)
- **Console-driven** - Interactive menu system in `console-menu` package
- **Configuration-based** - Template and config file driven attacks

### Concurrency Model

- Multi-threaded with configurable worker pools
- Atomic counters for thread-safe statistics
- Context-based cancellation for graceful shutdown
- Mutex protection for shared resources

### Data Management

- File-based configuration and data storage
- Automatic creation of required directories and files
- Template system for attack configurations
- Results logging to structured files

## Common Development Commands

```bash
# Run without building
go run cmd/letgo/main.go

# Run tests (if any exist)
go test ./...

# Format code
go fmt ./...

# Vet code for issues
go vet ./...

# Get dependencies
go mod tidy
```
