package provisioning

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
)

var (
	// versions embedded at build time.
	Version     = ""
	GitRevision = ""
)

// GetVersion returns the version embedded at build time.
func GetVersion() string {
	if Version == "" {
		return "custom"
	}
	return Version
}

// GetRevision returns the git revision embedded at build time.
func GetRevision() string {
	if GitRevision == "" {
		return "unknown"
	}
	return GitRevision
}


type ProvisioningConfig struct {
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	FragmentID   string `json:"fragment_id"`

	HotspotPrefix   string `json:"hotspot_prefix"`
	HotspotPassword string `json:"hotspot_password"`
}

func LoadProvisioningConfig(path string) (*ProvisioningConfig, error) {
	defaultConfig := &ProvisioningConfig{
		Manufacturer:    "viam",
		Model:           "custom",
		FragmentID:      "",
		HotspotPrefix:   "viam-setup",
		HotspotPassword: "viamsetup",
	}

	jsonBytes, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return defaultConfig, nil
		}
		return defaultConfig, err
	}

	newConfig := &ProvisioningConfig{}
	if err = json.Unmarshal(jsonBytes, newConfig); err != nil {
		return defaultConfig, err
	}

	return newConfig, nil
}


type Config struct {
	HotspotPassword string `json:"hotspot_password"`
	Networks []NetworkConfig `json:"networks"`
}

type NetworkConfig struct {
	Type string `json:"type"`
	SSID string `json:"ssid"`
	PSK  string `json:"psk"`
	Priority int `json:"priority"`
}

func LoadConfig(path string) (*Config, error) {
	jsonBytes, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &Config{}, nil
		}
		return &Config{}, err
	}

	newConfig := &Config{}
	if err = json.Unmarshal(jsonBytes, newConfig); err != nil {
		return &Config{}, err
	}

	return newConfig, nil
}
