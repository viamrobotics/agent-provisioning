// Package networkmanager is a wrapper around the upstream go NetworkManager api, and is the core of the project.
package networkmanager

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync"
	"time"

	gnm "github.com/Wifx/gonetworkmanager/v2"
	"github.com/google/uuid"
	errw "github.com/pkg/errors"
	"go.uber.org/zap"

	provisioning "github.com/viamrobotics/agent-provisioning"
	"github.com/viamrobotics/agent-provisioning/portal"
)

const (
	DNSMasqFilepath          = "/etc/NetworkManager/dnsmasq-shared.d/80-viam.conf"
	DNSMasqContentsRedirect  = "address=/#/10.42.0.1\n"
	DNSMasqContentsSetupOnly = "address=/.setup/10.42.0.1\n"

	ConnCheckFilepath = "/etc/NetworkManager/conf.d/80-viam.conf"
	ConnCheckContents = "[connectivity]\nuri=http://packages.viam.com/check_network_status.txt\ninterval=300\n"
)

var (
	BindAddr = "10.42.0.1:80"
	// older networkmanager requires unit32 arrays for IP addresses.
	ipAsUint32 = binary.LittleEndian.Uint32([]byte{10, 42, 0, 1})
)

type NMWrapper struct {
	workers sync.WaitGroup

	// only set during NewNMWrapper, no lock
	nm       gnm.NetworkManager
	dev      gnm.DeviceWireless
	settings gnm.Settings
	cp       *portal.CaptivePortal
	hostname string
	logger   *zap.SugaredLogger
	pCfg     provisioning.ProvisioningConfig

	// internal locking
	state *connectionState

	// requires locking
	mu           sync.Mutex
	lastScanTime time.Time
	visibleSSIDs []string
	knownSSIDs   map[string]gnm.Connection
	triedSSIDs   map[string]bool // union of knownSSIDs that have also been visible when NOT in provisioning mode
	hotspotConn  gnm.Connection
	hotspotSSID  string
	activeConn   gnm.ActiveConnection
}

func NewNMWrapper(logger *zap.SugaredLogger, pCfg *provisioning.ProvisioningConfig) (*NMWrapper, error) {
	nm, err := gnm.NewNetworkManager()
	if err != nil {
		return nil, err
	}

	settings, err := gnm.NewSettings()
	if err != nil {
		return nil, err
	}

	wrapper := &NMWrapper{
		pCfg:       *pCfg,
		logger:     logger,
		nm:         nm,
		settings:   settings,
		knownSSIDs: make(map[string]gnm.Connection),
		triedSSIDs: make(map[string]bool),
		state:      &connectionState{provisioningChange: time.Now()},
	}

	wrapper.hostname, err = settings.GetPropertyHostname()
	if err != nil {
		return nil, errw.Wrap(err, "error getting hostname from NetworkManager, is NetworkManager installed and enabled?")
	}

	err = wrapper.initWifiDev()
	if err != nil {
		return nil, err
	}

	err = wrapper.updateKnownConnections()
	if err != nil {
		return nil, err
	}

	connCheckEnabled, err := wrapper.nm.GetPropertyConnectivityCheckEnabled()
	if err != nil {
		return nil, (errw.Wrap(err, "error getting NetworkManager connectivity check state"))
	}

	if !connCheckEnabled {
		hasConnCheck, err := wrapper.nm.GetPropertyConnectivityCheckAvailable()
		if err != nil {
			return nil, (errw.Wrap(err, "error getting NetworkManager connectivity check configuration"))
		}

		if !hasConnCheck {
			if err := wrapper.writeConnCheck(); err != nil {
				return nil, (errw.Wrap(err, "error writing NetworkManager connectivity check configuration"))
			}
			if err := wrapper.nm.Reload(0); err != nil {
				return nil, (errw.Wrap(err, "error reloading NetworkManager"))
			}

			hasConnCheck, err = wrapper.nm.GetPropertyConnectivityCheckAvailable()
			if err != nil {
				return nil, (errw.Wrap(err, "error getting NetworkManager connectivity check configuration"))
			}
			if !hasConnCheck {
				return nil, (errors.New("error configuring NetworkManager connectivity check"))
			}
		}

		connCheckEnabled, err = wrapper.nm.GetPropertyConnectivityCheckEnabled()
		if err != nil {
			return nil, (errw.Wrap(err, "error getting NetworkManager connectivity check state"))
		}

		if !connCheckEnabled {
			return nil, errors.New("NetworkManager connectivity checking disabled by user, network management will be unavailable")
		}
	}

	return wrapper, nil
}

func (w *NMWrapper) GetOnline() (bool, time.Time, time.Time) {
	return w.state.getOnline()
}

func (w *NMWrapper) GetProvisioning() (bool, time.Time) {
	return w.state.getProvisioning()
}

func (w *NMWrapper) CheckOnline() (bool, error) {
	ok, err := w.nm.GetPropertyConnectivityCheckEnabled()
	if err != nil {
		return false, err
	}
	if !ok {
		return false, errors.New("NetworkManager connectivity checking is disabled, please reinstall this subsystem")
	}

	state, err := w.nm.State()
	if err != nil {
		return false, err
	}

	var online bool
	//nolint:exhaustive
	switch state {
	case gnm.NmStateConnectedGlobal:
		online = true
	case gnm.NmStateConnectedSite:
		fallthrough
	case gnm.NmStateConnectedLocal:
		// do nothing, but may need these two in the future
	case gnm.NmStateUnknown:
		err = errors.New("unable to determine network state")
	default:
		err = nil
	}

	w.state.setOnline(online)
	return online, err
}

func (w *NMWrapper) initWifiDev() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	devices, err := w.nm.GetDevices()
	if err != nil {
		return err
	}

	for _, device := range devices {
		devType, err := device.GetPropertyDeviceType()
		if err != nil {
			return err
		}
		if devType == gnm.NmDeviceTypeWifi {
			wifiDev, ok := device.(gnm.DeviceWireless)
			if ok {
				w.dev = wifiDev
				return w.dev.SetPropertyAutoConnect(true)
			}
		}
	}
	return fmt.Errorf("cannot find wifi device")
}

func (w *NMWrapper) updateKnownConnections() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	conns, err := w.settings.ListConnections()
	if err != nil {
		return err
	}

	for _, conn := range conns {
		settings, err := conn.GetSettings()
		if err != nil {
			return err
		}

		// First run, we may not have our hotspot saved.
		if w.hotspotConn == nil {
			connProps, ok := settings["connection"]
			if !ok {
				continue
			}

			idRaw, ok := connProps["id"]
			if !ok {
				continue
			}

			id, ok := idRaw.(string)
			if !ok {
				continue
			}

			if id == w.pCfg.HotspotPrefix {
				w.hotspotConn = conn
				continue
			}
		}

		// hunt down the ssid
		wifi, ok := settings["802-11-wireless"]
		if !ok {
			continue
		}

		modeRaw, ok := wifi["mode"]
		if !ok {
			continue
		}

		mode, ok := modeRaw.(string)
		if !ok || mode != "infrastructure" {
			continue
		}

		ssidRaw, ok := wifi["ssid"]
		if !ok {
			continue
		}
		ssidBytes, ok := ssidRaw.([]byte)
		if !ok {
			continue
		}
		if len(ssidBytes) == 0 {
			continue
		}
		w.knownSSIDs[string(ssidBytes)] = conn
	}

	w.hotspotSSID = w.pCfg.HotspotPrefix + "-" + strings.ToLower(w.hostname)
	if len(w.hotspotSSID) > 32 {
		w.hotspotSSID = w.hotspotSSID[:32]
	}
	if w.hotspotConn == nil {
		conn, err := w.settings.AddConnection(w.getSettingsHotspot(w.pCfg.HotspotPrefix, w.hotspotSSID, w.pCfg.HotspotPassword))
		if err != nil {
			return err
		}
		w.hotspotConn = conn
	} else {
		err = w.hotspotConn.Update(w.getSettingsHotspot(w.pCfg.HotspotPrefix, w.hotspotSSID, w.pCfg.HotspotPassword))
		if err != nil {
			return err
		}
	}

	return nil
}

func (w *NMWrapper) getSettingsWifi(id, ssid, psk string, priority int) gnm.ConnectionSettings {
	settings := gnm.ConnectionSettings{
		"connection": map[string]interface{}{
			"id":                   id,
			"uuid":                 uuid.New().String(),
			"type":                 "802-11-wireless",
			"autoconnect":          true,
			"autoconnect-priority": priority,
		},
		"802-11-wireless": map[string]interface{}{
			"mode": "infrastructure",
			"ssid": []byte(ssid),
		},
	}
	if psk != "" {
		settings["802-11-wireless-security"] = map[string]interface{}{"key-mgmt": "wpa-psk", "psk": psk}
	}
	return settings
}

func (w *NMWrapper) getSettingsHotspot(id, ssid, psk string) gnm.ConnectionSettings {
	settings := gnm.ConnectionSettings{
		"connection": map[string]interface{}{
			"id":          id,
			"uuid":        uuid.New().String(),
			"type":        "802-11-wireless",
			"autoconnect": false,
		},
		"802-11-wireless": map[string]interface{}{
			"mode": "ap",
			"ssid": []byte(ssid),
		},
		"802-11-wireless-security": map[string]interface{}{
			"key-mgmt": "wpa-psk",
			"psk":      psk,
		},
		"ipv4": map[string]interface{}{
			"method":    "shared",
			"addresses": [][]uint32{{ipAsUint32, 24, ipAsUint32}},
		},
		"ipv6": map[string]interface{}{
			"method": "disabled",
		},
	}
	return settings
}

func (w *NMWrapper) WifiScan(ctx context.Context) error {
	prevScan, err := w.dev.GetPropertyLastScan()
	if err != nil {
		return errw.Wrap(err, "error scanning wifi")
	}

	err = w.dev.RequestScan()
	if err != nil {
		return errw.Wrap(err, "error scanning wifi")
	}

	var lastScan int64
	for {
		lastScan, err = w.dev.GetPropertyLastScan()
		if err != nil {
			return errw.Wrap(err, "error scanning wifi")
		}
		if lastScan > prevScan {
			break
		}
		select {
		case <-ctx.Done():
			return errw.Wrap(ctx.Err(), "error scanning wifi")
		case <-time.After(time.Second):
		}
	}

	wifiList, err := w.dev.GetAccessPoints()
	if err != nil {
		return errw.Wrap(err, "error scanning wifi")
	}

	ssids := make(map[string]bool)
	for _, ap := range wifiList {
		ssid, err := ap.GetPropertySSID()
		if err != nil {
			return errw.Wrap(err, "error scanning wifi")
		}
		if ssid != w.hotspotSSID {
			ssids[ssid] = true
		}
	}

	var visibleSSIDs []string
	for ssid := range ssids {
		visibleSSIDs = append(visibleSSIDs, ssid)
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	w.lastScanTime = time.Now()
	w.visibleSSIDs = visibleSSIDs

	// mark ssids that are visible and known
	for _, ssid := range visibleSSIDs {
		_, ok := w.knownSSIDs[ssid]
		if !ok {
			continue
		}
		_, ok = w.triedSSIDs[ssid]
		if !ok {
			w.triedSSIDs[ssid] = false
		}
	}

	return nil
}

func (w *NMWrapper) MarkSSIDsTried() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for k := range w.triedSSIDs {
		w.triedSSIDs[k] = true
	}
}

// StartProvisioning puts the wifi in hotspot mode and starts a captive portal.
func (w *NMWrapper) StartProvisioning(ctx context.Context, prevErr error) (<-chan WifiSettings, error) {
	// mark any SSIDs as already "tested" before we start scanning ourselves
	w.MarkSSIDsTried()

	w.mu.Lock()
	provisioningMode, _ := w.state.getProvisioning()
	if provisioningMode {
		w.mu.Unlock()
		return nil, errors.New("provisioning mode already started")
	}

	if err := w.writeDNSMasq(); err != nil {
		w.mu.Unlock()
		return nil, (errw.Wrap(err, "error writing dnsmasq configuration during provisioning mode startup"))
	}

	activeConn, err := w.nm.ActivateConnection(w.hotspotConn, w.dev, nil)
	if err != nil {
		w.mu.Unlock()
		return nil, errw.Wrap(err, "error activating hotspot")
	}
	w.activeConn = activeConn

	var hotspotActive bool
	timeoutCtx, cancel := context.WithTimeout(ctx, time.Second*30)
	defer cancel()
	for {
		state, err := w.activeConn.GetPropertyState()
		if err != nil {
			w.activeConn = nil
			w.mu.Unlock()
			return nil, err
		}
		if state == gnm.NmActiveConnectionStateActivated {
			hotspotActive = true
			break
		}
		if timeoutCtx.Err() != nil {
			break
		}
	}

	if !hotspotActive {
		w.mu.Unlock()
		return nil, errors.New("could not activate provisioning hotspot")
	}

	// start portal with ssid list and known connections
	w.cp = portal.NewPortal(w.logger, BindAddr)
	w.cp.Run()
	w.state.setProvisioning(true)
	w.mu.Unlock()

	w.workers.Add(1)
	go func() {
		defer w.workers.Done()
		for {
			provisioningMode, _ := w.state.getProvisioning()
			if !provisioningMode {
				return
			}
			err := w.WifiScan(ctx)
			if err != nil {
				w.logger.Error(err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second * 15):
			}
		}
	}()

	settingsChan := make(chan WifiSettings)
	w.workers.Add(1)
	go func() {
		defer w.workers.Done()
		defer close(settingsChan)

		for {
			provisioningMode, _ := w.state.getProvisioning()
			if !provisioningMode {
				return
			}
			// loop waiting for input
			w.mu.Lock()
			ssid, psk, ok := w.cp.GetUserInput()
			if ok {
				settingsChan <- WifiSettings{SSID: ssid, PSK: psk}
				w.mu.Unlock()
				continue
			}
			var knownSSIDs []string
			for k := range w.knownSSIDs {
				knownSSIDs = append(knownSSIDs, k)
				tried, ok := w.triedSSIDs[k]
				// if a new SSID has appeared that needs to be tried, we send blank credentials to let provisioning mode exit
				if ok && !tried {
					settingsChan <- WifiSettings{}
					w.mu.Unlock()
					continue
				}
			}
			w.cp.SetData(w.visibleSSIDs, knownSSIDs, prevErr)

			// end loop
			w.mu.Unlock()
			if !provisioning.HealthySleep(ctx, time.Second) {
				break
			}
		}
	}()

	return settingsChan, nil
}

func (w *NMWrapper) StopProvisioning() error {
	provisioningMode, _ := w.state.getProvisioning()
	if !provisioningMode {
		return errors.New("provisioning mode not yet started")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.state.setProvisioning(false)
	var err error
	if w.cp != nil {
		err = w.cp.Stop()
	}
	w.cp = nil

	if w.activeConn != nil {
		err = errors.Join(err, w.nm.DeactivateConnection(w.activeConn))
	}
	return err
}

func (w *NMWrapper) Close() {
	provisioningMode, _ := w.state.getProvisioning()

	if provisioningMode {
		err := w.StopProvisioning()
		if err != nil {
			w.logger.Error(err)
		}
	}
	w.workers.Wait()
}

func (w *NMWrapper) GetLastInteraction() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cp == nil {
		return time.Time{}
	}
	return w.cp.GetLastInteraction()
}

func (w *NMWrapper) ActivateConnection(ssid string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	conSettings, ok := w.knownSSIDs[ssid]
	if !ok {
		return errw.Errorf("no settings found for ssid: %s", ssid)
	}
	_, err := w.nm.ActivateConnection(conSettings, w.dev, nil)
	return err
}

func (w *NMWrapper) CheckKnownSSIDs() bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	online := false
	for ssid := range w.knownSSIDs {
		w.logger.Debugf("checking known SSIDs", "ssid", ssid)
		err := w.ActivateConnection(ssid)

		if err == nil {
			online = true
			break
		}

		w.logger.Debugf("error connecting to ssid", "ssid", ssid, "err", err)
	}

	return online
}

func (w *NMWrapper) AddOrUpdateConnection(cfg provisioning.NetworkConfig) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if cfg.Type != "wifi" {
		return errw.Errorf("unspported network type %s, only 'wifi' currently supported", cfg.Type)
	}

	var err error
	settings := w.getSettingsWifi(w.pCfg.Manufacturer+"-"+cfg.SSID, cfg.SSID, cfg.PSK, cfg.Priority)
	newConn, ok := w.knownSSIDs[cfg.SSID]
	if !ok {
		newConn, err = w.settings.AddConnection(settings)
		if err != nil {
			return err
		}
		w.knownSSIDs[cfg.SSID] = newConn
		return nil
	}
	return newConn.Update(settings)
}

func (w *NMWrapper) writeDNSMasq() error {
	DNSMasqContents := DNSMasqContentsRedirect
	if w.pCfg.DisableDNSRedirect {
		DNSMasqContents = DNSMasqContentsSetupOnly
	}

	fileBytes, err := os.ReadFile(DNSMasqFilepath)
	if err == nil && bytes.Equal(fileBytes, []byte(DNSMasqContents)) {
		return nil
	}

	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	//nolint:gosec
	return os.WriteFile(DNSMasqFilepath, []byte(DNSMasqContents), 0o644)
}

func (w *NMWrapper) writeConnCheck() error {
	fileBytes, err := os.ReadFile(ConnCheckFilepath)
	if err == nil && bytes.Equal(fileBytes, []byte(ConnCheckContents)) {
		return nil
	}

	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	//nolint:gosec
	return os.WriteFile(ConnCheckFilepath, []byte(ConnCheckContents), 0o644)
}

type connectionState struct {
	mu sync.Mutex

	online       bool
	onlineChange time.Time
	lastOnline   time.Time

	provisioningMode   bool
	provisioningChange time.Time
}

func (c *connectionState) setOnline(online bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	c.online = online
	c.onlineChange = now
	if online {
		c.lastOnline = now
	}
}

func (c *connectionState) getOnline() (bool, time.Time, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.online, c.onlineChange, c.lastOnline
}

func (c *connectionState) setProvisioning(mode bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	c.provisioningMode = mode
	c.provisioningChange = now
}

func (c *connectionState) getProvisioning() (bool, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.provisioningMode, c.provisioningChange
}

type WifiSettings struct {
	SSID     string
	PSK      string
	Priority int
}
