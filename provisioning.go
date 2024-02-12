// Package provisioning holds utility functions and structures used by other modules in this project.
package provisioning

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"
	pb "go.viam.com/api/provisioning/v1"
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

	HotspotPrefix      string `json:"hotspot_prefix"`
	HotspotPassword    string `json:"hotspot_password"`
	DisableDNSRedirect bool   `json:"disable_dns_redirect"`
}

type NetworkInfo struct {
	Type      string
	SSID      string
	Security  string
	Signal    int32
	Connected bool
	LastError string
}

func NetworkInfoToProto(net *NetworkInfo) *pb.NetworkInfo {
	return &pb.NetworkInfo{
		Type:      net.Type,
		Ssid:      net.SSID,
		Security:  net.Security,
		Signal:    net.Signal,
		Connected: net.Connected,
		LastError: net.LastError,
	}
}

func NetworkInfoFromProto(buf *pb.NetworkInfo) *NetworkInfo {
	return &NetworkInfo{
		Type:      buf.GetType(),
		SSID:      buf.GetSsid(),
		Security:  buf.GetSecurity(),
		Signal:    buf.GetSignal(),
		Connected: buf.GetConnected(),
		LastError: buf.GetLastError(),
	}
}

type NetworkConfig struct {
	Type     string `json:"type"`
	SSID     string `json:"ssid"`
	PSK      string `json:"psk"`
	Priority int    `json:"priority"`
}

// DeviceConfig represents the minimal needed for /etc/viam.json.
type DeviceConfig struct {
	Cloud *CloudConfig `json:"cloud"`
}

type CloudConfig struct {
	AppAddress string `json:"app_address"`
	ID         string `json:"id"`
	Secret     string `json:"secret"`
}

func WriteDeviceConfig(file string, input *UserInput) error {
	if input.RawConfig != "" {
		return os.WriteFile(file, []byte(input.RawConfig), 0o600)
	}

	cfg := &DeviceConfig{
		Cloud: &CloudConfig{
			AppAddress: input.AppAddr,
			ID:         input.PartID,
			Secret:     input.Secret,
		},
	}

	jsonBytes, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(file, jsonBytes, 0o600)
}

type UserInput struct {
	Updated time.Time

	// network
	SSID string
	PSK  string

	// device credentials
	PartID  string
	Secret  string
	AppAddr string

	// raw /etc/viam.json contents
	RawConfig string
}

func LoadProvisioningConfig(path string) (*ProvisioningConfig, error) {
	defaultConf := ProvisioningConfig{
		Manufacturer:    "viam",
		Model:           "custom",
		FragmentID:      "",
		HotspotPrefix:   "viam-setup",
		HotspotPassword: "viamsetup",
	}
	//nolint:gosec
	jsonBytes, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &defaultConf, nil
		}
		return &defaultConf, err
	}
	conf := defaultConf
	if err = json.Unmarshal(jsonBytes, &conf); err != nil {
		return &defaultConf, err
	}

	if conf.Manufacturer == "" || conf.Model == "" || conf.HotspotPrefix == "" || conf.HotspotPassword == "" {
		return &defaultConf, errors.Errorf("values in %s cannot be empty, please omit empty fields entirely", path)
	}

	return &conf, nil
}

type Config struct {
	HotspotPassword string          `json:"hotspot_password"`
	Networks        []NetworkConfig `json:"networks"`
}

func LoadConfig(path string) (*Config, error) {
	//nolint:gosec
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

type ContextKey string

const HCReqKey = ContextKey("healthcheck")

// HealthySleep allows a process to sleep while stil responding to context cancellation AND healthchecks. Returns false if cancelled.
func HealthySleep(ctx context.Context, timeout time.Duration) bool {
	hc, ok := ctx.Value(HCReqKey).(*atomic.Bool)
	if !ok {
		// this should never happen, so avoiding having to pass a logger by just printing
		//nolint:forbidigo
		fmt.Println("context passed to HealthySleep without healthcheck value")
	}

	stop := &atomic.Bool{}
	defer stop.Store(true)

	go func() {
		for {
			if hc.Swap(false) {
				//nolint:forbidigo
				fmt.Println("HEALTHY")
			}
			if stop.Load() {
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(timeout):
			return true
		}
	}
}
