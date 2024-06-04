// Package networkmanager is a wrapper around the upstream go NetworkManager api, and is the core of the project.
package networkmanager

import (
	"context"
	"errors"
	"os"
	"sort"
	"strings"
	"time"

	gnm "github.com/Otterverse/gonetworkmanager/v2"
	errw "github.com/pkg/errors"
	"go.uber.org/zap"

	provisioning "github.com/viamrobotics/agent-provisioning"
	"github.com/viamrobotics/agent-provisioning/portal"
)

func NewNMWrapper(
	ctx context.Context,
	logger *zap.SugaredLogger,
	pCfg *provisioning.Config,
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

func (w *NMWrapper) getVisibleNetworks() []provisioning.NetworkInfo {
	w.dataMu.Lock()
	defer w.dataMu.Unlock()

	var visible []provisioning.NetworkInfo
	for _, nw := range w.networks {
		if nw.lastSeen.After(time.Now().Add(time.Minute*-1)) && !nw.isHotspot {
			visible = append(visible, nw.getInfo())
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
	return nw.getInfo()
}

// SMURF TODO logic around this for single mode.
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

// StartProvisioning puts the wifi in hotspot mode and starts a captive portal.
func (w *NMWrapper) StartProvisioning(ctx context.Context, userInputChan chan struct{}) error {
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
	go w.provisioningBackgroundLoop(ctx, cp, userInputChan)

	w.state.setProvisioning(true)
	return nil
}

func (w *NMWrapper) provisioningBackgroundLoop(ctx context.Context, cp *portal.CaptivePortal, userInputChan chan struct{}) {
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

		// signal that the user sent stuff so we can break the main loop
		userInputChan <- struct{}{}
	}
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
	if ssid != w.hotspotSSID {
		w.lastSSID = ssid
	}

	w.logger.Infof("Activating connection for SSID: %s", ssid)
	activeConnection, err := w.nm.ActivateConnection(nw.conn, w.dev, nil)
	if err != nil {
		nw.lastError = err
		return errw.Wrapf(err, "error activating connection for ssid: %s", ssid)
	}

	if err := w.waitForConnect(ctx); err != nil {
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

func (w *NMWrapper) waitForConnect(ctx context.Context) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	changeChan := make(chan gnm.DeviceStateChange, 32)
	exitChan := make(chan struct{})
	defer close(exitChan)

	if err := w.dev.SubscribeState(changeChan, exitChan); err != nil {
		return errw.Wrap(err, "monitoring connection activation")
	}

	for {
		select {
		case update := <-changeChan:
			w.logger.Debugf("%s->%s (%s)", update.OldState, update.NewState, update.Reason)
			//nolint:exhaustive
			switch update.NewState {
			case gnm.NmDeviceStateActivated:
				return nil
			case gnm.NmDeviceStateFailed:
				if update.Reason == gnm.NmDeviceStateReasonNoSecrets {
					return ErrBadPassword
				}
				// custom error if it's some other reason for failure
				return errw.Errorf("connection failed: %s", update.Reason)
			default:
			}

		case <-timeoutCtx.Done():
			return errw.Wrap(ctx.Err(), "waiting for network activation")
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

	settings := generateWifiSettings(w.pCfg.Manufacturer+"-"+cfg.SSID, cfg.SSID, cfg.PSK, cfg.Priority)
	if cfg.Type == "hotspot" {
		if cfg.SSID != w.hotspotSSID {
			return errors.New("only the builtin provisioning hotspot may use the 'hotspot' network type")
		}
		nw.isHotspot = true
		settings = generateHotspotSettings(w.pCfg.HotspotPrefix, w.hotspotSSID, w.pCfg.HotspotPassword)
	}

	if !w.pCfg.RoamingMode {
		// lower the priority of any existing/prior primary network
		w.lowerMaxNetPriorities(cfg.SSID)
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

// this doesn't error as it's not technically fatal if it fails.
func (w *NMWrapper) lowerMaxNetPriorities(skip string) {
	for ssid, nw := range w.networks {
		if ssid == skip || ssid == w.hotspotSSID || nw.priority < 999 {
			continue
		}

		if nw.conn != nil {
			settings, err := nw.conn.GetSettings()
			if err != nil {
				nw.conn = nil
				w.logger.Warnf("error (%s) encountered when getting settings for %s", err, nw.ssid)
				continue
			}

			if getPriorityFromSettings(settings) == 999 {
				settings["connection"]["autoconnect-priority"] = 998
				if err := nw.conn.Update(settings); err != nil {
					nw.conn = nil
					w.logger.Warnf("error (%s) encountered when updating settings for %s", err, nw.ssid)
				}
			}
			nw.priority = 998
		}
	}
}

func (w *NMWrapper) checkConfigured() {
	_, err := os.ReadFile(w.cfgPath)
	w.state.setConfigured(err == nil)
}

// tryCandidates returns true if a network activated.
func (w *NMWrapper) tryCandidates(ctx context.Context) bool {
	for _, ssid := range w.getCandidates() {
		// SMURF add debug logging around this
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

	userInputChan := make(chan struct{}, 1)
	var userInputReceived bool

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-userInputChan:
			userInputReceived = true
			// wait 3 seconds so responses can be sent to/seen by user
			if !provisioning.HealthySleep(ctx, time.Second*3) {
				return nil
			}
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
			inactivePortal := w.cp.GetLastInteraction().Before(now.Add(time.Duration(w.pCfg.UserTimeout)*-1)) || userInputReceived

			// exit/retry to test networks only if there's no recent user interaction AND configuration is present
			haveCandidates := len(w.getCandidates()) > 0 && inactivePortal && isConfigured

			// exit/retry every FallbackTimeout (10 minute default), unless user is active
			tenMinutes := pModeChange.Before(now.Add(time.Duration(w.pCfg.FallbackTimeout)*-1)) && inactivePortal

			shouldExit := allGood || haveCandidates || tenMinutes

			if shouldExit {
				if err := w.StopProvisioning(); err != nil {
					w.logger.Error(err)
				} else {
					pMode, _ = w.state.getProvisioning()
				}
			}
		}

		if allGood || pMode {
			continue
		}

		// not in provisioning mode
		if !isOnline {
			if w.tryCandidates(ctx) {
				isOnline, lastOnline = w.state.getOnline()
				if isOnline {
					continue
				}
			}
		}

		// not in provisioning mode, so start it if not configured (/etc/viam.json)
		// OR as long as we've been offline for at least OfflineTimeout (2 minute default)
		if !isConfigured || (lastOnline.Before(now.Add(time.Duration(w.pCfg.OfflineTimeout) * -1))) {
			if err := w.StartProvisioning(ctx, userInputChan); err != nil {
				w.logger.Error(err)
			}
		}
	}
}
