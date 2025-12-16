package networkmapper

import (
	"fmt"
)

// DefaultProfileManager implements the ProfileManager interface
type DefaultProfileManager struct {
	configManager *ConfigManager
}

// NewProfileManager creates a new DefaultProfileManager instance
func NewProfileManager() ProfileManager {
	return &DefaultProfileManager{
		configManager: NewConfigManager(),
	}
}

// GetProfile retrieves a scan profile by name
// Implements Requirements 7.1, 7.2, 7.3, 7.4, 7.5
func (pm *DefaultProfileManager) GetProfile(name string) (*ScanProfile, error) {
	if name == "" {
		return nil, fmt.Errorf("profile name cannot be empty")
	}

	// Try to load custom profile first
	profile, err := pm.configManager.LoadProfile(name)
	if err == nil {
		return profile, nil
	}

	// If not found, check default profiles
	defaultProfiles := pm.configManager.getDefaultProfiles()
	for _, defaultProfile := range defaultProfiles {
		if defaultProfile.Name == name {
			return &defaultProfile, nil
		}
	}

	return nil, fmt.Errorf("profile not found: %s", name)
}

// SaveProfile saves a custom scan profile
// Implements Requirements 7.5
func (pm *DefaultProfileManager) SaveProfile(profile ScanProfile) error {
	if profile.Name == "" {
		return fmt.Errorf("profile name cannot be empty")
	}

	// Don't allow overwriting default profiles
	if pm.configManager.isDefaultProfile(profile.Name) {
		return fmt.Errorf("cannot overwrite default profile: %s", profile.Name)
	}

	return pm.configManager.SaveProfile(profile)
}

// ListProfiles returns all available scan profiles
// Implements Requirements 7.1, 7.2, 7.3, 7.4, 7.5
func (pm *DefaultProfileManager) ListProfiles() []ScanProfile {
	profiles, err := pm.configManager.ListProfiles()
	if err != nil {
		// Return only default profiles if there's an error reading custom profiles
		return pm.configManager.getDefaultProfiles()
	}

	return profiles
}

// DeleteProfile removes a custom scan profile
// Implements Requirements 7.5
func (pm *DefaultProfileManager) DeleteProfile(name string) error {
	if name == "" {
		return fmt.Errorf("profile name cannot be empty")
	}

	return pm.configManager.DeleteProfile(name)
}
