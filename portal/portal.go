// Package portal is the web portal and grpc server for provisioning.
package portal

import (
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	errw "github.com/pkg/errors"
	"go.uber.org/zap"
	pb "go.viam.com/api/provisioning/v1"
	"google.golang.org/grpc"

	provisioning "github.com/viamrobotics/agent-provisioning"
)

type CaptivePortal struct {
	logger *zap.SugaredLogger

	bindAddr   string
	server     *http.Server
	grpcServer *grpc.Server

	factory *provisioning.ProvisioningConfig

	mu              sync.Mutex
	lastInteraction time.Time
	input           *provisioning.UserInput
	inputReceived   atomic.Bool
	status          *deviceStatus

	workers sync.WaitGroup
	pb.UnimplementedProvisioningServiceServer
}

type deviceStatus struct {
	banner           string
	lastNetwork      provisioning.NetworkInfo
	visibleNetworks  []provisioning.NetworkInfo
	online           bool
	deviceConfigured bool
	errors           []error
}

type templateData struct {
	Manufacturer string
	Model        string
	FragmentID   string

	Banner       string
	LastNetwork  provisioning.NetworkInfo
	VisibleSSIDs []provisioning.NetworkInfo
	Errors       []string
	IsConfigured bool
	IsOnline     bool
}

//go:embed templates/*
var templates embed.FS

func NewPortal(logger *zap.SugaredLogger, bindAddr string, factoryCfg provisioning.ProvisioningConfig) *CaptivePortal {
	mux := http.NewServeMux()
	cp := &CaptivePortal{
		bindAddr: bindAddr,
		logger:   logger,
		server: &http.Server{
			Addr:        bindAddr + ":80",
			Handler:     mux,
			ReadTimeout: time.Second * 10,
		},
		factory: &factoryCfg,
		input:   &provisioning.UserInput{},
		status:  &deviceStatus{},
	}
	mux.HandleFunc("/", cp.index)
	mux.HandleFunc("/save", cp.saveWifi)
	return cp
}

func (cp *CaptivePortal) Run() error {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	if err := cp.startGRPC(); err != nil {
		return errw.Wrap(err, "error starting GRPC service")
	}

	if err := cp.startWeb(); err != nil {
		return errw.Wrap(err, "error starting web portal service")
	}

	return nil
}

func (cp *CaptivePortal) startWeb() error {
	bind := cp.bindAddr + ":80"
	lis, err := net.Listen("tcp", bind)
	if err != nil {
		return errw.Wrapf(err, "error listening on: %s", bind)
	}

	cp.workers.Add(1)
	go func() {
		defer cp.workers.Done()
		err := cp.server.Serve(lis)
		if !errors.Is(err, http.ErrServerClosed) {
			cp.logger.Error(err)
		}
	}()
	return nil
}

func (cp *CaptivePortal) Stop() error {
	cp.mu.Lock()
	defer cp.mu.Unlock()

	if cp.grpcServer != nil {
		cp.grpcServer.Stop()
		cp.grpcServer = nil
	}

	var err error
	if cp.server != nil {
		err = cp.server.Close()
	}

	cp.input = &provisioning.UserInput{}
	cp.inputReceived.Store(false)

	return err
}

func (cp *CaptivePortal) GetUserInput() *provisioning.UserInput {
	if cp.inputReceived.Load() {
		cp.mu.Lock()
		defer cp.mu.Unlock()
		input := cp.input
		// in case both network and device credentials are being updated
		// only send user data after we've had it for ten seconds or if both are already set
		if time.Now().After(input.Updated.Add(time.Second*10)) ||
			(input.SSID != "" && input.PartID != "") ||
			(input.SSID != "" && cp.status.deviceConfigured) ||
			(input.PartID != "" && cp.status.online) {
			cp.input = &provisioning.UserInput{}
			cp.inputReceived.Store(false)
			return input
		}
	}
	return nil
}

func (cp *CaptivePortal) GetLastInteraction() time.Time {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.lastInteraction
}

func (cp *CaptivePortal) AppendErrors(errs ...error) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.status.errors = append(cp.status.errors, errs...)
}

func (cp *CaptivePortal) SetData(online, configured bool,
	networks []provisioning.NetworkInfo,
	lastTry provisioning.NetworkInfo,
) {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.status.online = online
	cp.status.deviceConfigured = configured
	cp.status.visibleNetworks = networks
	cp.status.lastNetwork = lastTry
}

func (cp *CaptivePortal) index(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := r.Body.Close(); err != nil {
			cp.logger.Error(err)
		}
	}()

	cp.mu.Lock()
	defer cp.mu.Unlock()
	cp.lastInteraction = time.Now()

	data := templateData{
		Manufacturer: cp.factory.Manufacturer,
		Model:        cp.factory.Model,
		FragmentID:   cp.factory.FragmentID,
		Banner:       cp.status.banner,
		LastNetwork:  cp.status.lastNetwork,
		VisibleSSIDs: cp.status.visibleNetworks,
		IsOnline:     cp.status.online,
		IsConfigured: cp.status.deviceConfigured,
		Errors:       cp.errListAsStrings(),
	}

	t, err := template.ParseFS(templates, "templates/*.html")
	if err != nil {
		cp.logger.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	if os.Getenv("VIAM_AGENT_DEVMODE") != "" {
		cp.logger.Warn("devmode enabled, using templates from /opt/viam/tmp/templates/")
		newT, err := template.ParseGlob("/opt/viam/tmp/templates/*.html")
		if err == nil {
			t = newT
		}
	}

	err = t.Execute(w, data)
	if err != nil {
		cp.logger.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	// reset the errors and banner, as they were now just displayed
	cp.status.banner = ""
	cp.status.errors = nil
}

func (cp *CaptivePortal) saveWifi(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := r.Body.Close(); err != nil {
			cp.logger.Error(err)
		}
	}()

	if r.Method == http.MethodPost {
		cp.mu.Lock()
		defer cp.mu.Unlock()
		defer http.Redirect(w, r, "/", http.StatusSeeOther)
		cp.lastInteraction = time.Now()

		ssid := r.FormValue("ssid")
		psk := r.FormValue("password")
		rawConfig := r.FormValue("viamconfig")

		if ssid == "" && !cp.status.online {
			cp.status.errors = append(cp.status.errors, errors.New("no SSID provided"))
			return
		}

		if rawConfig == "" && !cp.status.deviceConfigured {
			cp.status.errors = append(cp.status.errors, errors.New("no device config provided"))
			return
		}

		if rawConfig != "" {
			// we'll check if the config is valid, but NOT use the parsed config, in case additional fields on in the json
			cfg := &provisioning.DeviceConfig{}
			if err := json.Unmarshal([]byte(rawConfig), cfg); err != nil {
				cp.status.errors = append(cp.status.errors, errw.Wrap(err, "invalid json config contents"))
				return
			}
			if cfg.Cloud.ID == "" || cfg.Cloud.Secret == "" || cfg.Cloud.AppAddress == "" {
				cp.status.errors = append(cp.status.errors, errors.New("incomplete cloud config provided"))
				return
			}
			cp.input.RawConfig = rawConfig
			cp.logger.Debug("saving raw device config")
			cp.status.banner = "Saving device config. "
		}

		if ssid != "" {
			cp.input.SSID = ssid
			cp.input.PSK = psk
			cp.logger.Debugf("saving credentials for %s", cp.input.SSID)
			cp.status.banner += "Added credentials for SSID: " + cp.input.SSID
		}

		if ssid == cp.status.lastNetwork.SSID {
			cp.status.lastNetwork.LastError = ""
		}
		cp.input.Updated = time.Now()
		cp.inputReceived.Store(true)
	}
}
