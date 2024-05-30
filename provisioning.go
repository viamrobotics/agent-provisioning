// Package provisioning holds utility functions and structures used by other modules in this project.
package provisioning

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync/atomic"
	"time"

	errw "github.com/pkg/errors"
	pb "go.viam.com/api/provisioning/v1"
)

var (
	// versions embedded at build time.
	Version     = ""
	GitRevision = ""
)

var DefaultConf = Config{
	Manufacturer:       "viam",
	Model:              "custom",
	FragmentID:         "",
	HotspotPrefix:      "viam-setup",
	HotspotPassword:    "viamsetup",
	DisableDNSRedirect: false,
	RoamingMode:        false,
	OfflineTimeout:     Timeout(time.Minute * 2),
	UserTimeout:        Timeout(time.Minute * 5),
	FallbackTimeout:    Timeout(time.Minute * 10),
	Networks:           []NetworkConfig{},
}

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

func LoadConfig(defaultConf Config, path string) (*Config, error) {
	minTimeout := Timeout(time.Second * 15)

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
		return &defaultConf, errw.New("values in configs/attributes should not be empty, please omit empty fields entirely")
	}

	// SMURF TODO: figure out individual min/max timeouts allowed
	if conf.OfflineTimeout < minTimeout || conf.UserTimeout < minTimeout || conf.FallbackTimeout < minTimeout {
		return &defaultConf, errw.New("timeout values cannot be less than 15 seconds")
	}

	return &conf, nil
}

// Config represents the json configurations parsed from either agent-provisioning.json OR passed from the "attributes" in the cloud config.
type Config struct {
	// Things typically set in agent-provisioning.json
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	FragmentID   string `json:"fragment_id"`

	// The prefix to prepend to the hotspot name.
	HotspotPrefix string `json:"hotspot_prefix"`
	// Password required to connect to the hotspot.
	HotspotPassword string `json:"hotspot_password"`
	// If true, mobile (phone) users connecting to the hotspot won't be automatically redirected to the web portal.
	DisableDNSRedirect bool `json:"disable_dns_redirect"`

	// When true, will try all known networks looking for internet (global) connectivity.
	// Otherwise, will only try the primary wifi network and consider that sufficient if connected (regardless of global connectivity.)
	RoamingMode bool `json:"roaming_mode"`

	// How long without a connection before starting provisioning (hotspot) mode.
	OfflineTimeout Timeout `json:"offline_timeout"`

	// How long since the last user interaction (via GRPC/app or web portal) before the state machine can resume.
	UserTimeout Timeout `json:"user_timeout"`

	// If not "online", always drop out of hotspot mode and retry everything after this time limit.
	FallbackTimeout Timeout `json:"fallback_timeout"`

	// Additional networks to always add/configure.
	Networks []NetworkConfig `json:"networks"`
}

// Timeout allows parsing golang-style durations (1h20m30s) OR seconds-as-float from/to json.
type Timeout time.Duration

func (t Timeout) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(t).String())
}

func (t *Timeout) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case float64:
		*t = Timeout(value * float64(time.Second))
		return nil
	case string:
		tmp, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		*t = Timeout(tmp)
		return nil
	default:
		return errw.Errorf("invalid duration: %+v", v)
	}
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
