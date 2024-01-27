package networkmanager

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	errw "github.com/pkg/errors"

	gnm "github.com/Wifx/gonetworkmanager/v2"
	"go.uber.org/zap"

	"github.com/google/uuid"

	provisioning "github.com/viamrobotics/agent-provisioning"
	"github.com/viamrobotics/agent-provisioning/portal"
)

type NMWrapper struct {
	workers sync.WaitGroup

	// only set during NewNMWrapper, no lock
	nm gnm.NetworkManager
	dev gnm.DeviceWireless
	settings gnm.Settings
	cp *portal.CaptivePortal
	hostname string
	logger *zap.SugaredLogger
	pCfg provisioning.ProvisioningConfig

	// internal locking
	state *connectionState

	// requires locking
	mu sync.Mutex
	lastOnlineTime time.Time
	lastScanTime time.Time
	visibleSSIDs []string
	knownSSIDs map[string]gnm.Connection
	triedSSIDs map[string]bool // union of knownSSIDs that have also been visible when NOT in provisioning mode
	hotspotConn gnm.Connection
	activeConn gnm.ActiveConnection
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
		pCfg: *pCfg,
		logger: logger,
		nm: nm,
		settings: settings,
		knownSSIDs: make(map[string]gnm.Connection),
		triedSSIDs: make(map[string]bool),
		state: &connectionState{bootstrapChange: time.Now()},
	}

	wrapper.hostname, err = settings.GetPropertyHostname()
	if err != nil {
		return nil, err
	}

	err = wrapper.initWifiDev()
	if err != nil {
		return nil, err
	}

	err = wrapper.updateKnownConnections()
	if err != nil {
		return nil, err
	}

	return wrapper, nil
}

func (w *NMWrapper) GetOnline() (bool, time.Time, time.Time) {
	return w.state.getOnline()
}

func (w *NMWrapper) GetBootstrap() (bool, time.Time) {
	return w.state.getBootstrap()
}

func (w *NMWrapper) CheckOnline() (bool, error) {
	ok, err := w.nm.GetPropertyConnectivityCheckEnabled()
	if err != nil {
		return false, err
	}
	if !ok {
		return false, errors.New("NetworkManager connectivity checking is disabled. Please reinstall this subsystem.")
	}

	state, err := w.nm.State()
	if err != nil {
		return false, err
	}

	var online bool
	switch state {
	case gnm.NmStateConnectedGlobal:
		online = true
	case gnm.NmStateConnectedSite:
		fallthrough
	case gnm.NmStateConnectedLocal:
		//err = errors.New("network has limited connectivity, no internet")
	case gnm.NmStateUnknown:
		err = errors.New("unable to determine network state")
	default:
		err = nil
	}

	w.state.setOnline(online)
	return online, err
}


func (w *NMWrapper) initWifiDev() (error) {
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
				return nil
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

	hotspotSSID := w.pCfg.HotspotPrefix + "-" + strings.ToLower(w.hostname)
	if len(hotspotSSID) > 32 {
		hotspotSSID = hotspotSSID[:32]
	}
	if w.hotspotConn == nil {
		conn, err := w.settings.AddConnection(w.getSettingsHotspot(w.pCfg.HotspotPrefix, hotspotSSID, w.pCfg.HotspotPassword))
		if err != nil {
			return err
		}
		w.hotspotConn = conn
	} else {
		err = w.hotspotConn.Update(w.getSettingsHotspot(w.pCfg.HotspotPrefix, hotspotSSID, w.pCfg.HotspotPassword))
		if err != nil {
			return err
		}
	}

	return nil
}

func (w *NMWrapper) getSettingsWifi(id, ssid, psk string, priority int) (gnm.ConnectionSettings) {
	settings := gnm.ConnectionSettings{
		"connection": map[string]interface{}{
			"id": id,
			"uuid": uuid.New().String(),
			"type": "802-11-wireless",
			"autoconnect": true,
			"autoconnect-priority": priority,
		},
		"802-11-wireless": map[string]interface{}{
			"mode": "infrastructure",
			"ssid": []byte(ssid),
		},
		"802-11-wireless-security": map[string]interface{}{
			"key-mgmt": "wpa-psk",
			"psk": psk,
		},
	}
	return settings
}

func (w *NMWrapper) getSettingsHotspot(id, ssid, psk string) (gnm.ConnectionSettings) {

	// SMURF TODO write /etc/NetworkManager/dnsmasq-shared.d/10-viam.conf:
	// address=/#/10.42.0.1

	// older networkmanager requires unit32 arrays for IP addresses.
	ipAsUint32 := binary.LittleEndian.Uint32([]byte{10, 42, 0, 1})

	settings := gnm.ConnectionSettings{
		"connection": map[string]interface{}{
			"id": id,
			"uuid": uuid.New().String(),
			"type": "802-11-wireless",
		},
		"802-11-wireless": map[string]interface{}{
			"mode": "ap",
			"ssid": []byte(ssid),
		},
		"802-11-wireless-security": map[string]interface{}{
			"key-mgmt": "wpa-psk",
			"psk": psk,
		},
		"ipv4": map[string]interface{}{
			"method": "shared",
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
		return err
	}

	err = w.dev.RequestScan()
	if err != nil {
		return err
	}

	var lastScan int64
	for {
		lastScan, err = w.dev.GetPropertyLastScan()
		if err != nil {
			return err
		}
		if lastScan > prevScan {
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		time.Sleep(time.Second)
	}

	wifiList, err := w.dev.GetAccessPoints()
	if err != nil {
		return err
	}

	ssids := make(map[string]bool)
	for _, ap := range wifiList {
		ssid, err :=ap.GetPropertySSID()
		if err != nil {
			return err
		}
		ssids[ssid] = true
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

// bootstrap put the wifi in hotspot mode and starts a captive portal
func (w *NMWrapper) StartBootstrap(prevErr error) (<-chan WifiSettings, error){
	w.logger.Debug("startBootstrap 1")

	// mark any SSIDs as already "tested" before we start scanning ourselves
	w.MarkSSIDsTried()

	w.mu.Lock()
	w.logger.Debug("startBootstrap 2")

	bs, _ := w.state.getBootstrap()
	if bs {
		w.mu.Unlock()
		return nil, errors.New("bootstrap mode already started")
	}

	activeConn, err := w.nm.ActivateConnection(w.hotspotConn, w.dev, nil)
	if err != nil {
		w.logger.Error(err)
	}
	w.activeConn = activeConn

	err = w.startIPTables()
	if err != nil {
		w.logger.Error(err)
	}

	w.logger.Debug("startBootstrap 3")

	// start portal with ssid list and known connections
	w.cp = portal.NewPortal()
	w.cp.Run()
	w.logger.Debug("startBootstrap 4")
	w.state.setBootstrap(true)
	w.mu.Unlock()
	w.logger.Debug("startBootstrap 5")

	w.workers.Add(1)
	go func(){
		defer w.workers.Done()
		for {
			bs, _ := w.state.getBootstrap()
			if !bs{
				return
			}
			w.WifiScan(context.TODO())
			time.Sleep(time.Second * 15)
		}
	}()

	settingsChan := make(chan WifiSettings)
	w.workers.Add(1)
	go func() {
		//w.logger.Debug("bs loop 1")
		defer w.workers.Done()
		defer close(settingsChan)

		for {
			//w.logger.Debug("bs loop 2")
			bs, _ := w.state.getBootstrap()
			if !bs{
				return
			}
			// loop waiting for input
			w.mu.Lock()
			//w.logger.Debug("bs loop 4")
			ssid, psk, ok := w.cp.GetUserInput()
			if ok {
			//	w.logger.Debug("bs loop 5")
				w.logger.Debugf("send chan: %+v", settingsChan)
				settingsChan <- WifiSettings{SSID: ssid, PSK: psk}
				w.mu.Unlock()
				continue
			}
			//w.logger.Debug("bs loop 6")
			var knownSSIDs []string
			for k := range w.knownSSIDs {
				knownSSIDs = append(knownSSIDs, k)
				tried, ok := w.triedSSIDs[k]
				// if a new SSID has appeared that needs to be tried, we send blank credentials to let bootstrap mode exit
				if ok && !tried {
					settingsChan <- WifiSettings{}
					w.mu.Unlock()
					continue
				}

			}
			//w.logger.Debug("bs loop 7")
			w.cp.SetData(w.visibleSSIDs, knownSSIDs, prevErr)

			// end loop
			w.mu.Unlock()
			//w.logger.Debug("bs loop 8")
			time.Sleep(time.Second)
		}
	}()
	w.logger.Debug("startBootstrap 6")

	return settingsChan, nil
}


func (w *NMWrapper) StopBootstrap() error {
	bs, _ := w.state.getBootstrap()
	if !bs {
		return errors.New("bootstrap mode not yet started")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.state.setBootstrap(false)
	err := w.cp.Stop()
	w.cp = nil

	err = errors.Join(err, w.stopIPTables())
	if w.activeConn != nil {
		err = errors.Join(err, w.nm.DeactivateConnection(w.activeConn))
	}
	return err
}


func (w *NMWrapper) Close() {
	bs, _ := w.state.getBootstrap()

	if bs {
		err := w.StopBootstrap()
		if err != nil {
			fmt.Println(err)
		}
	}
	w.workers.Wait()
}

func (w *NMWrapper) GetLastInteraction() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cp != nil {
		return time.Time{}
	}
	return w.cp.GetLastInteraction()
}

func (w *NMWrapper) AddOrUpdateConnection(cfg provisioning.NetworkConfig) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if cfg.Type != "wifi" {
		return errw.Errorf("unspported network type %s, only 'wifi' currently supported", cfg.Type)
	}

	var err error
	settings := w.getSettingsWifi(w.pCfg.Manufacturer + "-" + cfg.SSID, cfg.SSID, cfg.PSK, cfg.Priority)
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

func (w *NMWrapper) startIPTables() error {

	// SMURF TODO get wlan0 and IP address from live system

	cmd := exec.Command("bash", "-c", "iptables -t nat -A PREROUTING -p tcp -m tcp -i wlan0 --dport 80 -j DNAT --to-destination 10.42.0.1:8888")
	out, err := cmd.CombinedOutput()
	if err != nil {
		w.logger.Error(out)
	}
	return err
}

func (w *NMWrapper) stopIPTables() error {

	// SMURF TODO get wlan0 and IP address from live system

	cmd := exec.Command("bash", "-c", "iptables -t nat -D PREROUTING -p tcp -m tcp -i wlan0 --dport 80 -j DNAT --to-destination 10.42.0.1:8888")
	out, err := cmd.CombinedOutput()
	if err != nil {
		w.logger.Error(out)
	}
	return err
}

type connectionState struct {
	mu sync.Mutex

	online bool
	onlineChange time.Time
	lastOnline time.Time

	bootstrapMode bool
	bootstrapChange time.Time
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

func (c *connectionState) setBootstrap(mode bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	c.bootstrapMode = mode
	c.bootstrapChange = now
}

func (c *connectionState) getBootstrap() (bool, time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bootstrapMode, c.bootstrapChange
}

type WifiSettings struct {
	SSID string
	PSK string
	Priority int
}
