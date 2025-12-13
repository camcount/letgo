package paths

import (
	"os"
	"path/filepath"
	"strings"
)

// GetDataDir returns the path to the application data directory
// It handles multiple scenarios:
// 1. Dev mode (go run): Uses application/data relative to project root
// 2. Built executable in application folder: Uses data subfolder of executable
// 3. Built executable elsewhere: Uses data subfolder of executable (creates if missing)
func GetDataDir() string {
	// First, check current working directory for dev mode (go run)
	// This handles the case when running from project root
	wd, err := os.Getwd()
	if err == nil {
		wdAbs, err := filepath.Abs(wd)
		if err == nil {
			// Check if we're in the project root (has application folder)
			appDir := filepath.Join(wdAbs, "application")
			if _, err := os.Stat(appDir); err == nil {
				// application folder exists, use application/data
				dataDir := filepath.Join(wdAbs, "application", "data")
				os.MkdirAll(dataDir, 0755)
				return dataDir
			}
			
			// Check if we're already in application directory
			wdName := filepath.Base(wdAbs)
			if wdName == "application" {
				dataDir := filepath.Join(wdAbs, "data")
				os.MkdirAll(dataDir, 0755)
				return dataDir
			}
		}
	}
	
	// Get the executable's directory for built executables
	exePath, err := os.Executable()
	if err == nil {
		exeDir, err := filepath.Abs(filepath.Dir(exePath))
		if err == nil {
			// Check if executable is in a temp directory (go run scenario)
			// Also check if path contains "go-build" which indicates go run
			tempDir := os.TempDir()
			isTempDir := strings.Contains(strings.ToLower(exeDir), strings.ToLower(tempDir)) || 
			            strings.Contains(exeDir, "go-build")
			
			if !isTempDir {
				exeDirName := filepath.Base(exeDir)
				
				// If executable is in "application" directory, use "data" subdirectory
				if exeDirName == "application" {
					dataDir := filepath.Join(exeDir, "data")
					os.MkdirAll(dataDir, 0755)
					return dataDir
				}
				
				// Executable is elsewhere - use data folder next to executable
				// This handles the case when user copies letgo.exe to another location
				dataDir := filepath.Join(exeDir, "data")
				os.MkdirAll(dataDir, 0755)
				return dataDir
			}
		}
	}
	
	// Final fallback: use application/data relative to current working directory
	wd, err = os.Getwd()
	if err == nil {
		wdAbs, err := filepath.Abs(wd)
		if err == nil {
			dataDir := filepath.Join(wdAbs, "application", "data")
			os.MkdirAll(dataDir, 0755)
			return dataDir
		}
	}
	
	// Last resort: relative path (should rarely reach here)
	return "application/data"
}

