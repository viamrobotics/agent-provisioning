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
)

func NewNMWrapper(
	ctx context.Context,
	logger *zap.SugaredLogger,
	cfg *provisioning.Config,
	viamCfgPath string,
) (*NMWrapper, error) {
	nm, err := gnm.NewNetworkManager()
	if err != nil {
		return nil, err
	}

	settings, err := gnm.NewSettings()
	if err != nil {
		return nil, err
	}

	logger.Debugf("Config: %+v", cfg)

	w := &NMWrapper{
		cfg:         *cfg,
		viamCfgPath: viamCfgPath,
		logger:      logger,
		nm:          nm,
		settings:    settings,
		networks:    make(map[string]*network),
		state:       &connectionState{logger: logger},
		input:       &provisioning.UserInput{},
	}

	w.hostname, err = settings.GetPropertyHostname()
	if err != nil {
		return nil, errw.Wrap(err, "error getting hostname from NetworkManager, is NetworkManager installed and enabled?")
	}

	w.hotspotSSID = w.cfg.HotspotPrefix + "-" + strings.ToLower(w.hostname)
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

	w.checkConfigured()
	if err := w.networkScan(ctx); err != nil {
		return nil, err
	}
	if err := w.checkConnection(); err != nil {
		return nil, err
	}

	return w, nil
}

func (w *NMWrapper) Close() {
	if w.state.getProvisioning() {
		err := w.StopProvisioning()
		if err != nil {
			w.logger.Error(err)
		}
	}
	w.monitorWorkers.Wait()
}

func (w *NMWrapper) getVisibleNetworks() []provisioning.NetworkInfo {
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
	nw, ok := w.networks[w.lastSSID]
	if !ok {
		nw = &network{}
	}
	return nw.getInfo()
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

func (w *NMWrapper) checkConnection() error {
	var connected bool
	defer func() {
		w.state.setConnected(connected)
	}()

	activeConnection, err := w.dev.GetPropertyActiveConnection()
	if err != nil {
		return err
	}

	if activeConnection == nil {
		return nil
	}

	connection, err := activeConnection.GetPropertyConnection()
	if err != nil {
		return err
	}

	settings, err := connection.GetSettings()
	if err != nil {
		return err
	}

	ssid := getSSIDFromSettings(settings)

	w.dataMu.Lock()
	w.activeSSID = ssid
	defer w.dataMu.Unlock()
	activeNetwork, ok := w.networks[w.activeSSID]
	if !ok {
		err := errw.Errorf("active network not found in network list: %s", w.activeSSID)
		w.activeSSID = ""
		return err
	}

	activeNetwork.activeConn = activeConnection

	state, err := activeNetwork.activeConn.GetPropertyState()
	if err != nil {
		err = errw.Wrapf(err, "getting state of active connection: %s", w.activeSSID)
		// active connection will be removed from dbus once its no longer active, so we nil it out
		activeNetwork.activeConn = nil
		activeNetwork.connected = false
		w.activeSSID = ""
		return err
	}
	// in roaming mode, we don't care WHAT network is connected
	if w.cfg.RoamingMode && state == gnm.NmActiveConnectionStateActivated && w.activeSSID != w.hotspotSSID {
		connected = true
		return nil
	}

	// in normal (single) mode, we need to be connected to the priority 999 network
	if state == gnm.NmActiveConnectionStateActivated && getPriorityFromSettings(settings) == 999 {
		connected = true
	}

	return nil
}

// StartProvisioning puts the wifi in hotspot mode and starts a captive portal.
func (w *NMWrapper) StartProvisioning(ctx context.Context) error {
	if w.state.getProvisioning() {
		return errors.New("provisioning mode already started")
	}

	w.opMu.Lock()
	defer w.opMu.Unlock()

	w.logger.Info("Starting provisioning mode.")
	if _, err := w.addOrUpdateConnection(provisioning.NetworkConfig{Type: NetworkTypeHotspot, SSID: w.hotspotSSID}); err != nil {
		return err
	}
	if err := w.activateConnection(ctx, w.hotspotSSID); err != nil {
		return errw.Wrap(err, "error starting provisioning mode hotspot")
	}

	// start portal with ssid list and known connections
	if err := w.startPortal(); err != nil {
		err = errors.Join(err, w.deactivateConnection(w.hotspotSSID))
		return errw.Wrap(err, "could not start web/grpc portal")
	}

	w.state.setProvisioning(true)
	return nil
}

func (w *NMWrapper) StopProvisioning() error {
	w.opMu.Lock()
	defer w.opMu.Unlock()
	w.logger.Info("Stopping provisioning mode.")
	w.state.setProvisioning(false)
	err := w.stopPortal()
	w.provisioningWorkers.Wait()
	err2 := w.deactivateConnection(w.hotspotSSID)
	if errors.Is(err2, ErrNoActiveConnectionFound) {
		return err
	}
	return errors.Join(err, err2)
}

func (w *NMWrapper) ActivateConnection(ctx context.Context, ssid string) error {
	if w.state.getProvisioning() {
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

	w.logger.Infof("Successfully activated connection for SSID: %s", ssid)

	if ssid != w.hotspotSSID {
		w.state.setConnected(true)
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

	w.logger.Infof("Successfully deactivated connection for SSID: %s", ssid)

	w.state.setConnected(false)
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
		default:
			if !provisioning.HealthySleep(timeoutCtx, time.Second) {
				return errw.Wrap(ctx.Err(), "waiting for network activation")
			}
		}
	}
}

func (w *NMWrapper) AddOrUpdateConnection(cfg provisioning.NetworkConfig) (bool, error) {
	w.opMu.Lock()
	defer w.opMu.Unlock()
	return w.addOrUpdateConnection(cfg)
}

// returns true if network was new (added) and not updated.
func (w *NMWrapper) addOrUpdateConnection(cfg provisioning.NetworkConfig) (bool, error) {
	var newNetwork bool

	if cfg.Type != NetworkTypeWifi && cfg.Type != NetworkTypeHotspot {
		return newNetwork, errw.Errorf("unspported network type %s, only %s currently supported", cfg.Type, NetworkTypeWifi)
	}

	if cfg.PSK != "" && len(cfg.PSK) < 8 {
		return newNetwork, errors.New("wifi passwords must be at least 8 characters long, or completely empty (for unsecured networks)")
	}

	w.dataMu.Lock()
	defer w.dataMu.Unlock()

	nw, ok := w.networks[cfg.SSID]
	if !ok {
		nw = &network{
			ssid:    cfg.SSID,
			netType: cfg.Type,
		}
		w.networks[cfg.SSID] = nw
	}

	nw.lastTried = time.Time{}
	nw.priority = cfg.Priority

	settings := generateWifiSettings(w.cfg.Manufacturer+"-"+cfg.SSID, cfg.SSID, cfg.PSK, cfg.Priority)
	if cfg.Type == NetworkTypeHotspot {
		if cfg.SSID != w.hotspotSSID {
			return newNetwork, errw.Errorf("only the builtin provisioning hotspot may use the %s network type", NetworkTypeHotspot)
		}
		nw.isHotspot = true
		settings = generateHotspotSettings(w.cfg.HotspotPrefix, w.hotspotSSID, w.cfg.HotspotPassword)
	}

	if !w.cfg.RoamingMode && cfg.Priority == 999 {
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
		newNetwork = true
		newConn, err := w.settings.AddConnection(settings)
		if err != nil {
			return newNetwork, errw.Wrap(err, "error adding new connection")
		}
		nw.conn = newConn
		return newNetwork, nil
	}
	return newNetwork, nil
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

				// deprecated fields that are read-only, so can't try to set them
				delete(settings["ipv6"], "addresses")
				delete(settings["ipv6"], "routes")

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
	_, err := os.ReadFile(w.viamCfgPath)
	w.state.setConfigured(err == nil)
}

// tryCandidates returns true if a network activated.
func (w *NMWrapper) tryCandidates(ctx context.Context) bool {
	for _, ssid := range w.getCandidates() {
		err := w.activateConnection(ctx, ssid)
		if err != nil {
			w.logger.Error(err)
			continue
		}

		// in single mode we just need a connection
		if !w.cfg.RoamingMode {
			return true
		}

		// in roaming mode we need full internet
		if w.state.getOnline() {
			return true
		}

		w.logger.Warnf("SSID %s connected, but does not provide internet access.", ssid)
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

		// firstSeen is reset if a network disappears for more than a minute, so retry if it comes back (or generally after 10 minutes)
		recentlyTried := nw.lastTried.After(nw.firstSeen) && nw.lastTried.After(time.Now().Add(time.Duration(w.cfg.FallbackTimeout)*-1))

		// must be either roaming mode OR priority 999 (in single mode)
		if !nw.isHotspot && visible && configured && !recentlyTried && (w.cfg.RoamingMode || nw.priority == 999) {
			candidates = append(candidates, nw.ssid)
		}
	}

	// this shouldn't happen without external network manipulation, but it's non-fatal, so just warn
	if !w.cfg.RoamingMode && len(candidates) > 1 {
		w.logger.Warnf("Multiple networks have highest (999) priority. Selection will be arbitrary.")
	}

	return candidates
}

func (w *NMWrapper) startStateMonitors(ctx context.Context) {
	if err := w.checkOnline(true); err != nil {
		w.logger.Error(err)
	}

	w.monitorWorkers.Add(1)
	go func() {
		defer w.monitorWorkers.Done()
		w.logger.Info("Background state monitors started")
		defer w.logger.Info("Background state monitors stopped")
		for {
			if !provisioning.Sleep(ctx, scanLoopDelay) {
				return
			}

			w.checkConfigured()
			if err := w.networkScan(ctx); err != nil {
				w.logger.Error(err)
			}
			if err := w.checkConnection(); err != nil {
				w.logger.Error(err)
			}
			if err := w.checkOnline(false); err != nil {
				w.logger.Error(err)
			}
		}
	}()
}

func (w *NMWrapper) StartMonitoring(ctx context.Context) error {
	w.startStateMonitors(ctx)

	var userInputReceived bool

	for {
		if !provisioning.HealthySleep(ctx, mainLoopDelay) {
			return nil
		}
		userInput := w.GetUserInput()
		if userInput != nil {
			if userInput.RawConfig != "" || userInput.PartID != "" {
				w.logger.Info("Device config received")
				err := provisioning.WriteDeviceConfig(w.viamCfgPath, *userInput)
				if err != nil {
					w.dataMu.Lock()
					w.errors = append(w.errors, err)
					w.dataMu.Unlock()
					w.logger.Error(err)
					continue
				}
				w.checkConfigured()
				userInputReceived = true
			}

			var newSSID string
			var newNetwork bool
			if userInput.SSID != "" {
				w.logger.Infof("Wifi settings received for %s", userInput.SSID)
				priority := int32(999)
				if w.cfg.RoamingMode {
					priority = 100
				}
				cfg := provisioning.NetworkConfig{
					Type:     "wifi",
					SSID:     userInput.SSID,
					PSK:      userInput.PSK,
					Priority: priority,
				}
				var err error
				newNetwork, err = w.AddOrUpdateConnection(cfg)
				if err != nil {
					w.dataMu.Lock()
					w.errors = append(w.errors, err)
					w.dataMu.Unlock()
					w.logger.Error(err)
					continue
				}
				userInputReceived = true
				newSSID = cfg.SSID
			}

			// wait 3 seconds so responses can be sent to/seen by user
			if !provisioning.HealthySleep(ctx, time.Second*3) {
				return nil
			}
			if newNetwork {
				err := w.StopProvisioning()
				if err != nil {
					w.logger.Error(err)
					continue
				}
				err = w.ActivateConnection(ctx, newSSID)
				if err != nil {
					w.logger.Error(err)
					continue
				}
				if !w.state.getOnline() {
					err := w.deactivateConnection(newSSID)
					if err != nil {
						w.logger.Error(err)
					}
					w.dataMu.Lock()
					nw, ok := w.networks[newSSID]
					if ok {
						// add a user warning for the portal
						err = errw.New("Network has no internet. Resubmit to use anyway.")
						nw.lastError = err
						w.logger.Warn(err)
					} else {
						w.logger.Error("cannot find ssid %s in network list", newSSID)
					}
					w.dataMu.Unlock()
					err = w.StartProvisioning(ctx)
					if err != nil {
						w.logger.Error(err)
					}
				}
			}
		}

		isOnline := w.state.getOnline()
		lastOnline := w.state.getLastOnline()
		isConnected := w.state.getConnected()
		lastConnected := w.state.getLastConnected()
		hasConnectivity := isConnected || isOnline
		lastConnectivity := lastConnected
		if lastOnline.After(lastConnected) {
			lastConnectivity = lastOnline
		}
		isConfigured := w.state.getConfigured()
		allGood := isConfigured && (isConnected || isOnline)
		if w.cfg.RoamingMode {
			allGood = isOnline && isConfigured
			hasConnectivity = isOnline
			lastConnectivity = lastOnline
		}
		pMode := w.state.getProvisioning()
		pModeChange := w.state.getProvisioningChange()
		now := time.Now()

		w.logger.Debugf("wifi connected: %t, internet reachable: %t, config present: %t", isConnected, isOnline, isConfigured)

		if pMode {
			// complex logic, so wasting some variables for readability

			// portal interaction time is updated when a user loads a page or makes a grpc request
			inactivePortal := w.state.getLastInteraction().Before(now.Add(time.Duration(w.cfg.UserTimeout)*-1)) || userInputReceived

			// exit/retry to test networks only if there's no recent user interaction AND configuration is present
			haveCandidates := len(w.getCandidates()) > 0 && inactivePortal && isConfigured

			// exit/retry every FallbackTimeout (10 minute default), unless user is active
			fallbackHit := pModeChange.Before(now.Add(time.Duration(w.cfg.FallbackTimeout)*-1)) && inactivePortal

			shouldExit := allGood || haveCandidates || fallbackHit

			w.logger.Debugf("inactive portal: %t, have candidates: %t, fallback timeout: %t", inactivePortal, haveCandidates, fallbackHit)

			if shouldExit {
				if err := w.StopProvisioning(); err != nil {
					w.logger.Error(err)
				} else {
					pMode = w.state.getProvisioning()
				}
			}
		}

		if allGood || pMode {
			continue
		}

		// not in provisioning mode
		if !hasConnectivity {
			if w.tryCandidates(ctx) {
				hasConnectivity = w.state.getConnected() || w.state.getOnline()
				// if we're roaming or this network was JUST added, it must have internet
				if w.cfg.RoamingMode {
					hasConnectivity = w.state.getOnline()
				}
				if hasConnectivity {
					continue
				}
				lastConnectivity = w.state.getLastConnected()
				if w.cfg.RoamingMode {
					lastConnectivity = w.state.getLastOnline()
				}
			}
		}

		// not in provisioning mode, so start it if not configured (/etc/viam.json)
		// OR as long as we've been offline for at least OfflineTimeout (2 minute default)
		if !isConfigured || lastConnectivity.Before(now.Add(time.Duration(w.cfg.OfflineTimeout)*-1)) {
			if err := w.StartProvisioning(ctx); err != nil {
				w.logger.Error(err)
			}
		}
	}
}
