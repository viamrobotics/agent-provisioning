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
	"sort"
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
	BindAddr = "10.42.0.1"
	// older networkmanager requires unit32 arrays for IP addresses.
	IPAsUint32                    = binary.LittleEndian.Uint32([]byte{10, 42, 0, 1})
	ErrCouldNotActivateConnection = errors.New("could not activate connection")
	ErrConnCheckDisabled          = errors.New("NetworkManager connectivity checking disabled by user, network management will be unavailable")
	ErrNoActiveConnectionFound    = errors.New("no active connection found")
	loopDelay                     = time.Second * 15
	connectTimeout                = time.Second * 30
)

type NMWrapper struct {
	monitorWorkers sync.WaitGroup
	pModeWorkers   sync.WaitGroup

	// blocks start/stop/etc operations
	opMu sync.Mutex

	// only set during NewNMWrapper, no lock
	nm       gnm.NetworkManager
	dev      gnm.DeviceWireless
	settings gnm.Settings
	cp       *portal.CaptivePortal
	hostname string
	logger   *zap.SugaredLogger
	pCfg     provisioning.ProvisioningConfig
	cfgPath  string

	// internal locking
	state *connectionState

	// locking for data updates
	dataMu      sync.Mutex
	networks    map[string]*network
	hotspotSSID string
	activeSSID  string
	lastSSID    string
}

func (w *NMWrapper) getVisibleNetworks() []provisioning.NetworkInfo {
	w.dataMu.Lock()
	defer w.dataMu.Unlock()

	var visible []provisioning.NetworkInfo
	for _, nw := range w.networks {
		if nw.lastSeen.After(time.Now().Add(time.Minute*-1)) && !nw.isHotspot {
			visible = append(visible, getNetworkInfo(nw))
		}
	}

	// sort by strongest signal
	sort.SliceStable(visible, func(i, j int) bool {
		return visible[i].Signal > visible[j].Signal
	})

	return visible
}

func (w *NMWrapper) getLastNetworkTried() provisioning.NetworkInfo {
	w.dataMu.Lock()
	defer w.dataMu.Unlock()
	nw, ok := w.networks[w.lastSSID]
	if !ok {
		nw = &network{}
	}
	return getNetworkInfo(nw)
}

type network struct {
	netType   string
	ssid      string
	security  string
	signal    uint8
	isHotspot bool

	firstSeen time.Time
	lastSeen  time.Time

	lastTried     time.Time
	connected     bool
	lastConnected time.Time
	lastError     error

	conn       gnm.Connection
	activeConn gnm.ActiveConnection
}

func getNetworkInfo(n *network) provisioning.NetworkInfo {
	var errStr string
	if n.lastError != nil {
		errStr = n.lastError.Error()
	}

	return provisioning.NetworkInfo{
		Type:      n.netType,
		SSID:      n.ssid,
		Security:  n.security,
		Signal:    int32(n.signal),
		Connected: n.connected,
		LastError: errStr,
	}
}

func NewNMWrapper(
	ctx context.Context,
	logger *zap.SugaredLogger,
	pCfg *provisioning.ProvisioningConfig,
	cfgPath string,
) (*NMWrapper, error) {
	nm, err := gnm.NewNetworkManager()
	if err != nil {
		return nil, err
	}

	settings, err := gnm.NewSettings()
	if err != nil {
		return nil, err
	}

	w := &NMWrapper{
		pCfg:     *pCfg,
		cfgPath:  cfgPath,
		logger:   logger,
		nm:       nm,
		settings: settings,
		networks: make(map[string]*network),
		state:    &connectionState{},
	}

	w.hostname, err = settings.GetPropertyHostname()
	if err != nil {
		return nil, errw.Wrap(err, "error getting hostname from NetworkManager, is NetworkManager installed and enabled?")
	}

	w.hotspotSSID = w.pCfg.HotspotPrefix + "-" + strings.ToLower(w.hostname)
	if len(w.hotspotSSID) > 32 {
		w.hotspotSSID = w.hotspotSSID[:32]
	}

	if err := w.writeDNSMasq(); err != nil {
		return nil, errw.Wrap(err, "error writing dnsmasq configuration")
	}

	if err := w.testConnCheck(); err != nil {
		return nil, err
	}

	if err := w.initWifiDev(); err != nil {
		return nil, err
	}

	if err = w.networkScan(ctx); err != nil {
		return nil, err
	}

	return w, nil
}

func (w *NMWrapper) testConnCheck() error {
	connCheckEnabled, err := w.nm.GetPropertyConnectivityCheckEnabled()
	if err != nil {
		return errw.Wrap(err, "error getting NetworkManager connectivity check state")
	}

	if !connCheckEnabled {
		hasConnCheck, err := w.nm.GetPropertyConnectivityCheckAvailable()
		if err != nil {
			return errw.Wrap(err, "error getting NetworkManager connectivity check configuration")
		}

		if !hasConnCheck {
			if err := w.writeConnCheck(); err != nil {
				return (errw.Wrap(err, "error writing NetworkManager connectivity check configuration"))
			}
			if err := w.nm.Reload(0); err != nil {
				return (errw.Wrap(err, "error reloading NetworkManager"))
			}

			hasConnCheck, err = w.nm.GetPropertyConnectivityCheckAvailable()
			if err != nil {
				return errw.Wrap(err, "error getting NetworkManager connectivity check configuration")
			}
			if !hasConnCheck {
				return errors.New("error configuring NetworkManager connectivity check")
			}
		}

		connCheckEnabled, err = w.nm.GetPropertyConnectivityCheckEnabled()
		if err != nil {
			return errw.Wrap(err, "error getting NetworkManager connectivity check state")
		}

		if !connCheckEnabled {
			return ErrConnCheckDisabled
		}
	}
	return nil
}

func (w *NMWrapper) initWifiDev() error {
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

func (w *NMWrapper) networkScan(ctx context.Context) error {
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
		if !provisioning.HealthySleep(ctx, time.Second) {
			return nil
		}
	}

	wifiList, err := w.dev.GetAccessPoints()
	if err != nil {
		return errw.Wrap(err, "error scanning wifi")
	}

	w.dataMu.Lock()
	defer w.dataMu.Unlock()

	// set "now" to be reusable for consistency
	now := time.Now()
	for _, ap := range wifiList {
		//nolint:nilerr
		if ctx.Err() != nil {
			return nil
		}
		ssid, err := ap.GetPropertySSID()
		if err != nil {
			w.logger.Error(errw.Wrap(err, "error scanning wifi"))
			continue
		}

		signal, err := ap.GetPropertyStrength()
		if err != nil {
			w.logger.Error(errw.Wrap(err, "error scanning wifi"))
			continue
		}

		apFlags, err := ap.GetPropertyFlags()
		if err != nil {
			w.logger.Error(errw.Wrap(err, "error scanning wifi"))
			continue
		}

		wpaFlags, err := ap.GetPropertyWPAFlags()
		if err != nil {
			w.logger.Error(errw.Wrap(err, "error scanning wifi"))
			continue
		}

		rsnFlags, err := ap.GetPropertyRSNFlags()
		if err != nil {
			w.logger.Error(errw.Wrap(err, "error scanning wifi"))
			continue
		}

		nw, ok := w.networks[ssid]
		if !ok {
			nw = &network{}
			w.networks[ssid] = nw
		}

		nw.netType = "wifi"
		nw.ssid = ssid
		nw.security = parseWPAFlags(apFlags, wpaFlags, rsnFlags)
		nw.signal = signal
		nw.lastSeen = now

		if nw.firstSeen.IsZero() {
			nw.firstSeen = now
		}
	}

	for _, nw := range w.networks {
		//nolint:nilerr
		if ctx.Err() != nil {
			return nil
		}

		// if a network isn't visible, reset the firstSeen time
		if nw.lastSeen.Before(time.Now().Add(time.Minute * -1)) {
			nw.firstSeen = time.Time{}
		}
	}

	return w.updateKnownConnections(ctx)
}

// updates connections/settings from those known to NetworkManager.
func (w *NMWrapper) updateKnownConnections(ctx context.Context) error {
	conns, err := w.settings.ListConnections()
	if err != nil {
		return err
	}

	for _, conn := range conns {
		//nolint:nilerr
		if ctx.Err() != nil {
			return nil
		}
		settings, err := conn.GetSettings()
		if err != nil {
			return err
		}

		ssid := getSSIDFromSettings(settings)

		if ssid == "" {
			// wired ethernet or some other type of connection
			continue
		}

		// actually record the network
		nw, ok := w.networks[ssid]
		if !ok {
			nw = &network{}
			w.networks[ssid] = nw
		}
		nw.conn = conn

		if ssid == w.hotspotSSID {
			nw.isHotspot = true
		}
	}

	return nil
}

func (w *NMWrapper) checkOnline(force bool) error {
	if force {
		if err := w.nm.CheckConnectivity(); err != nil {
			w.logger.Error(err)
		}
	}

	state, err := w.nm.State()
	if err != nil {
		return err
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
	return err
}

func getSSIDFromSettings(settings gnm.ConnectionSettings) string {
	// gnm.ConnectionSettings is a map[string]map[string]interface{}
	wifi, ok := settings["802-11-wireless"]
	if !ok {
		return ""
	}

	modeRaw, ok := wifi["mode"]
	if !ok {
		return ""
	}

	mode, ok := modeRaw.(string)
	// we'll take hotspots and "normal" infrastructure connections only
	if !ok || !(mode == "infrastructure" || mode == "ap") {
		return ""
	}

	ssidRaw, ok := wifi["ssid"]
	if !ok {
		return ""
	}
	ssidBytes, ok := ssidRaw.([]byte)
	if !ok {
		return ""
	}
	if len(ssidBytes) == 0 {
		return ""
	}
	return string(ssidBytes)
}

func getSettingsWifi(id, ssid, psk string, priority int) gnm.ConnectionSettings {
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

func getSettingsHotspot(id, ssid, psk string) gnm.ConnectionSettings {
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
			"addresses": [][]uint32{{IPAsUint32, 24, IPAsUint32}},
		},
		"ipv6": map[string]interface{}{
			"method": "disabled",
		},
	}
	return settings
}

// StartProvisioning puts the wifi in hotspot mode and starts a captive portal.
func (w *NMWrapper) StartProvisioning(ctx context.Context) error {
	provisioningMode, _ := w.state.getProvisioning()
	if provisioningMode {
		return errors.New("provisioning mode already started")
	}

	w.opMu.Lock()
	defer w.opMu.Unlock()

	w.logger.Info("Starting provisioning mode.")
	if err := w.addOrUpdateConnection(provisioning.NetworkConfig{Type: "hotspot", SSID: w.hotspotSSID}); err != nil {
		return err
	}
	if err := w.activateConnection(ctx, w.hotspotSSID); err != nil {
		return errw.Wrap(err, "error starting provisioning mode hotspot")
	}

	// start portal with ssid list and known connections
	cp := portal.NewPortal(w.logger, BindAddr, w.pCfg)
	w.dataMu.Lock()
	w.cp = cp
	w.dataMu.Unlock()
	if err := w.cp.Run(); err != nil {
		err = errors.Join(err, w.deactivateConnection(w.hotspotSSID))
		w.dataMu.Lock()
		w.cp = nil
		w.dataMu.Unlock()
		return errw.Wrap(err, "could not start web/grpc portal")
	}

	w.pModeWorkers.Add(1)
	go func() {
		defer w.pModeWorkers.Done()

		w.logger.Debug("provisioning background loop started")
		defer w.logger.Debug("provisioning background loop stopped")

		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}

			run, _ := w.state.getProvisioning()
			if !run {
				return
			}

			settings := cp.GetUserInput()
			if settings == nil {
				online, _ := w.state.getOnline()
				cp.SetData(online, w.state.getConfigured(), w.getVisibleNetworks(), w.getLastNetworkTried())
				continue
			}

			if settings.RawConfig != "" || settings.PartID != "" {
				w.logger.Debug("device config received")
				err := provisioning.WriteDeviceConfig(w.cfgPath, settings)
				if err != nil {
					cp.AppendErrors(err)
					w.logger.Error(err)
				}
			}

			if settings.SSID != "" {
				w.logger.Debugf("wifi settings received for %s", settings.SSID)
				cfg := provisioning.NetworkConfig{
					Type:     "wifi",
					SSID:     settings.SSID,
					PSK:      settings.PSK,
					Priority: 100,
				}

				err := w.AddOrUpdateConnection(cfg)
				if err != nil {
					cp.AppendErrors(err)
					w.logger.Error(err)
					continue
				}
			}
		}
	}()

	w.state.setProvisioning(true)
	return nil
}

func (w *NMWrapper) StopProvisioning() error {
	w.opMu.Lock()
	defer w.opMu.Unlock()
	w.logger.Info("Stopping provisioning mode.")
	w.state.setProvisioning(false)
	w.pModeWorkers.Wait()
	var err error

	w.dataMu.Lock()
	if w.cp != nil {
		err = w.cp.Stop()
	}
	w.cp = nil
	w.dataMu.Unlock()

	err2 := w.deactivateConnection(w.hotspotSSID)
	if errors.Is(err2, ErrNoActiveConnectionFound) {
		return err
	}
	return errors.Join(err, err2)
}

func (w *NMWrapper) Close() {
	provisioningMode, _ := w.state.getProvisioning()

	if provisioningMode {
		err := w.StopProvisioning()
		if err != nil {
			w.logger.Error(err)
		}
	}
	w.monitorWorkers.Wait()
}

func (w *NMWrapper) ActivateConnection(ctx context.Context, ssid string) error {
	provisioning, _ := w.state.getProvisioning()
	if provisioning {
		return errors.New("cannot activate another connection while in provisioning mode")
	}

	w.opMu.Lock()
	defer w.opMu.Unlock()
	return w.activateConnection(ctx, ssid)
}

func (w *NMWrapper) activateConnection(ctx context.Context, ssid string) error {
	w.dataMu.Lock()
	defer w.dataMu.Unlock()

	now := time.Now()

	nw, ok := w.networks[ssid]
	if !ok || nw.conn == nil {
		return errw.Errorf("no settings found for ssid: %s", ssid)
	}

	nw.lastTried = now
	w.lastSSID = ssid

	w.logger.Infof("Activating connection for SSID: %s", ssid)
	activeConnection, err := w.nm.ActivateConnection(nw.conn, w.dev, nil)
	if err != nil {
		nw.lastError = err
		return errw.Wrapf(err, "error activating connection for ssid: %s", ssid)
	}

	if err := waitForConnect(ctx, activeConnection); err != nil {
		nw.lastError = err
		return err
	}

	nw.connected = true
	nw.lastConnected = now
	nw.activeConn = activeConnection
	nw.lastError = nil
	w.activeSSID = ssid

	if ssid != w.hotspotSSID {
		return w.checkOnline(true)
	}

	return nil
}

func (w *NMWrapper) deactivateConnection(ssid string) error {
	w.dataMu.Lock()
	defer w.dataMu.Unlock()

	nw, ok := w.networks[ssid]
	if !ok || nw.activeConn == nil {
		return errw.Wrapf(ErrNoActiveConnectionFound, "ssid: %s", ssid)
	}

	w.logger.Infof("Deactivating connection for SSID: %s", ssid)

	if err := w.nm.DeactivateConnection(nw.activeConn); err != nil {
		nw.activeConn = nil
		nw.lastError = err
		return errw.Wrapf(err, "error deactivating connection for ssid: %s", ssid)
	}

	nw.connected = false
	nw.lastConnected = time.Now()
	nw.activeConn = nil
	nw.lastError = nil
	w.activeSSID = ""
	return nil
}

func waitForConnect(ctx context.Context, conn gnm.ActiveConnection) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	for {
		state, err := conn.GetPropertyState()
		if err != nil {
			// dbus errors are useless here, as when the connection fails, the object just goes away
			// so we report our own instead
			return ErrCouldNotActivateConnection
		}
		if state == gnm.NmActiveConnectionStateActivated {
			return nil
		}
		if !provisioning.HealthySleep(timeoutCtx, time.Second) {
			return errors.Join(err, ErrCouldNotActivateConnection)
		}
	}
}

func (w *NMWrapper) AddOrUpdateConnection(cfg provisioning.NetworkConfig) error {
	w.opMu.Lock()
	defer w.opMu.Unlock()
	return w.addOrUpdateConnection(cfg)
}

func (w *NMWrapper) addOrUpdateConnection(cfg provisioning.NetworkConfig) error {
	if cfg.Type != "wifi" && cfg.Type != "hotspot" {
		return errw.Errorf("unspported network type %s, only 'wifi' currently supported", cfg.Type)
	}

	if cfg.PSK != "" && len(cfg.PSK) < 8 {
		return errors.New("wifi passwords must be at least 8 characters long, or completely empty (for unsecured networks)")
	}

	w.dataMu.Lock()
	defer w.dataMu.Unlock()

	nw, ok := w.networks[cfg.SSID]
	if !ok {
		nw = &network{}
		w.networks[cfg.SSID] = nw
	}

	nw.lastTried = time.Time{}

	settings := getSettingsWifi(w.pCfg.Manufacturer+"-"+cfg.SSID, cfg.SSID, cfg.PSK, cfg.Priority)
	if cfg.Type == "hotspot" {
		if cfg.SSID != w.hotspotSSID {
			return errors.New("only the builtin provisioning hotspot may use the 'hotspot' network type")
		}
		nw.isHotspot = true
		settings = getSettingsHotspot(w.pCfg.HotspotPrefix, w.hotspotSSID, w.pCfg.HotspotPassword)
	}

	w.logger.Infof("Adding/updating settings for SSID %s", cfg.SSID)

	if nw.conn != nil {
		if err := nw.conn.Update(settings); err != nil {
			// we may be out of sync with NetworkManager
			nw.conn = nil
			w.logger.Warnf("error (%s) encountered when updating settings for %s, attempting to add as new network", err, nw.ssid)
		}
	}

	if nw.conn == nil {
		newConn, err := w.settings.AddConnection(settings)
		if err != nil {
			return errw.Wrap(err, "error adding new connection")
		}
		nw.conn = newConn
		return nil
	}
	return nil
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

func parseWPAFlags(apFlags, wpaFlags, rsnFlags uint32) string {
	flags := []string{}
	if apFlags&uint32(gnm.Nm80211APFlagsPrivacy) != 0 && wpaFlags == uint32(gnm.Nm80211APSecNone) && rsnFlags == uint32(gnm.Nm80211APSecNone) {
		return "WEP"
	}

	if wpaFlags == uint32(gnm.Nm80211APSecNone) && rsnFlags == uint32(gnm.Nm80211APSecNone) {
		return "-"
	}

	if wpaFlags != uint32(gnm.Nm80211APSecNone) {
		flags = append(flags, "WPA1")
	}
	if rsnFlags&uint32(gnm.Nm80211APSecKeyMgmtPSK) != 0 || rsnFlags&uint32(gnm.Nm80211APSecKeyMgmt8021X) != 0 {
		flags = append(flags, "WPA2")
	}
	if rsnFlags&uint32(gnm.Nm80211APSecKeyMgmtSAE) != 0 {
		flags = append(flags, "WPA3")
	}
	if rsnFlags&uint32(gnm.Nm80211APSecKeyMgmtOWE) != 0 {
		flags = append(flags, "OWE")
	} else if rsnFlags&uint32(gnm.Nm80211APSecKeyMgmtOWETM) != 0 {
		flags = append(flags, "OWE-TM")
	}
	if wpaFlags&uint32(gnm.Nm80211APSecKeyMgmt8021X) != 0 || rsnFlags&uint32(gnm.Nm80211APSecKeyMgmt8021X) != 0 {
		flags = append(flags, "802.1X")
	}

	return strings.Join(flags, " ")
}

func (w *NMWrapper) checkConfigured() {
	_, err := os.ReadFile(w.cfgPath)
	w.state.setConfigured(err == nil)
}

// tryCandidates returns true if a network activated.
func (w *NMWrapper) tryCandidates(ctx context.Context) bool {
	for _, ssid := range w.getCandidates() {
		if err := w.activateConnection(ctx, ssid); err == nil {
			return true
		}
	}
	return false
}

func (w *NMWrapper) getCandidates() []string {
	w.dataMu.Lock()
	defer w.dataMu.Unlock()
	var candidates []string
	for _, nw := range w.networks {
		// ssid seen within the past minute
		visible := nw.lastSeen.After(time.Now().Add(time.Minute * -1))

		// ssid has a connection known to network manager
		configured := nw.conn != nil

		// firstSeen is reset if a network disappears for more than a minute, so retry if it comes back
		recentlyTried := nw.lastTried.After(nw.firstSeen)

		if !nw.isHotspot && visible && configured && !recentlyTried {
			candidates = append(candidates, nw.ssid)
		}
	}
	return candidates
}

func (w *NMWrapper) startStateMonitors(ctx context.Context) {
	w.checkConfigured()
	if err := w.checkOnline(true); err != nil {
		w.logger.Error(err)
	}
	if err := w.networkScan(ctx); err != nil {
		w.logger.Error(err)
	}

	w.monitorWorkers.Add(1)
	go func() {
		defer w.monitorWorkers.Done()
		w.logger.Debug("background state monitors started")
		defer w.logger.Debug("background state monitors stopped")
		for {
			if !provisioning.HealthySleep(ctx, loopDelay) {
				return
			}

			w.checkConfigured()
			if err := w.checkOnline(false); err != nil {
				w.logger.Error(err)
			}
			if err := w.networkScan(ctx); err != nil {
				w.logger.Error(err)
			}
		}
	}()
}

func (w *NMWrapper) StartMonitoring(ctx context.Context) error {
	w.startStateMonitors(ctx)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(loopDelay):
		}

		isOnline, lastOnline := w.state.getOnline()
		isConfigured := w.state.getConfigured()
		allGood := isOnline && isConfigured
		pMode, pModeChange := w.state.getProvisioning()
		now := time.Now()

		w.logger.Debugf("online: %t, config_present: %t", isOnline, isConfigured)

		if pMode {
			// complex logic, so wasting some variables for readability

			// portal interaction time is updated when a user loads a page or makes a grpc request
			// it is reset (time.IsZero()==true) when a user actually submits config data
			inactivePortal := w.cp.GetLastInteraction().Before(now.Add(time.Minute * -5))

			// exit/retry to test networks only if there's no recent user interaction AND configuration is present
			haveCandidates := len(w.getCandidates()) > 0 && inactivePortal && isConfigured

			// exit/retry every ten minutes as a fallback, unless user is active
			tenMinutes := pModeChange.Before(now.Add(time.Minute*-10)) && inactivePortal

			shouldExit := allGood || haveCandidates || tenMinutes

			if shouldExit {
				if err := w.StopProvisioning(); err != nil {
					w.logger.Error(err)
				} else {
					pMode, pModeChange = w.state.getProvisioning()
				}
			}
		}

		// not in provisioning mode
		if allGood || pMode {
			continue
		}

		if !isOnline {
			if w.tryCandidates(ctx) {
				isOnline, lastOnline = w.state.getOnline()
				if isOnline {
					continue
				}
			}
		}

		// not in provisioning mode, so start it if not configured (/etc/viam.json)
		// OR as long as we've been offline for at least two minutes AND out of provisioning for two minutes
		twoMinutesAgo := now.Add(time.Minute * -2)
		if !isConfigured || (lastOnline.Before(twoMinutesAgo) && pModeChange.Before(twoMinutesAgo)) {
			if err := w.StartProvisioning(ctx); err != nil {
				w.logger.Error(err)
			}
		}
	}
}
