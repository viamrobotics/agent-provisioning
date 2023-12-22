package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	gnm "github.com/Wifx/gonetworkmanager/v2"
	"github.com/edaniels/golog"
	"github.com/google/uuid"

	"github.com/viamrobotics/agent-networking/portal"
)

const (
	connIDPrefix = "viam-"
	hotspotID = "Viam-Setup"
	hotspotSSIDPrefix = "viam-setup-"
	hotspotPassword = "viamsetup"
)

var (
	activeBackgroundWorkers sync.WaitGroup

	// only changed/set at startup, so no mutex.
	log = golog.NewDebugLogger("agent-networking")
)


func main() {

	// SMURF TODO signaled context
	ctx := setupExitSignalHandling()

	nm, err := NewNMWrapper()
	if err != nil {
		log.Fatal(err)
	}
	defer nm.Close()

	var prevError error
	for {
		log.Debug("sleeping")
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second * 15):
		}

		log.Debug("online check")

		online, err := nm.CheckOnline()
		if err != nil {
			log.Error(err)
			continue
		}

		log.Debug("actual online: ", online)


		// SMURF TESTING
		online = false

		if online {
			continue
		}

		// offline logic
		bs, _ := nm.state.getBootstrap()
		var settingsChan <-chan wifiSettings
		// not in bootstrap mode, so start it
		if !bs {
			log.Debug("offline")
			// SMURF restore below
			// _, _, lastOnline := nm.GetOnline()
			if true { // time.Now().After(lastOnline.Add(time.Minute * 2)) {
				log.Debug("starting bootstrap")
				settingsChan, err = nm.startBootstrap(prevError)
				if err != nil {
					log.Error(err)
				}
			} else {
				// offline but not for long enough yet
				continue
			}
		}

		// in bootstrap mode, wait for settings from user OR timeout

		log.Debug("bootstrap waiting")

		log.Debugf("recv chan: %+v", settingsChan)

		select {
		case settings := <-settingsChan:
			log.Debug("settings recieved")
			err := nm.AddOrUpdateConnection(settings.ssid, settings.psk)
			if err != nil {
				prevError = err
				log.Error(err)
				continue
			}

		case <-ctx.Done():
			log.Debug("context cancelled")
		case <-time.After(10 * time.Minute):
			log.Debug("10 minute timeout")
		}
		log.Debug("bootstrap stopping")

		err = nm.stopBootstrap()
		if err != nil {
			log.Error(err)
		}
	}
}

type wifiSettings struct {
	ssid string
	psk string
	priority int
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

type NMWrapper struct {

	workers sync.WaitGroup

	// only set during NewNMWrapper, no lock
	nm gnm.NetworkManager
	dev gnm.DeviceWireless
	settings gnm.Settings
	cp *portal.CaptivePortal
	hostname string

	// internal locking
	state *connectionState

	// requires locking
	mu sync.Mutex
	lastOnlineTime time.Time
	lastScanTime time.Time
	visibleSSIDs []string
	knownSSIDs map[string]gnm.Connection
	hotspotConn gnm.Connection
}

func NewNMWrapper() (*NMWrapper, error) {
	nm, err := gnm.NewNetworkManager()
	if err != nil {
		return nil, err
	}

	settings, err := gnm.NewSettings()
	if err != nil {
		return nil, err
	}

	wrapper := &NMWrapper{nm: nm, settings: settings, state: &connectionState{}}

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
		err = errors.New("network has limited connectivity, no internet")
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
	w.knownSSIDs = make(map[string]gnm.Connection)

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

			if id == hotspotID {
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

	hotspotSSID := hotspotSSIDPrefix + strings.ToLower(w.hostname)
	if len(hotspotSSID) > 32 {
		hotspotSSID = hotspotSSID[:32]
	}
	if w.hotspotConn == nil {
		conn, err := w.settings.AddConnection(w.getSettingsHotspot(hotspotID, hotspotSSID, hotspotPassword))
		if err != nil {
			return err
		}
		w.hotspotConn = conn
	} else {
		err = w.hotspotConn.Update(w.getSettingsHotspot(hotspotID, hotspotSSID, hotspotPassword))
		if err != nil {
			return err
		}
	}

	return nil
}


func getSettingsWifi(id, ssid, psk string) (gnm.ConnectionSettings) {
	settings := gnm.ConnectionSettings{
		"connection": map[string]interface{}{
			"id": id,
			"uuid": uuid.New().String(),
			"type": "802-11-wireless",
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
		},
		"ipv6": map[string]interface{}{
			"method": "ignore",
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

	ssids := make([]string, len(wifiList))

	for n, ap := range wifiList {
		ssid, err :=ap.GetPropertySSID()
		if err != nil {
			return err
		}
		ssids[n] = ssid
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	w.lastScanTime = time.Now()
	w.visibleSSIDs = ssids
	return nil
}



// bootstrap put the wifi in hotspot mode and starts a captive portal
func (w *NMWrapper) startBootstrap(prevErr error) (<-chan wifiSettings, error){
	log.Debug("startBootstrap 1")
	w.mu.Lock()
	log.Debug("startBootstrap 2")

	bs, _ := w.state.getBootstrap()
	if bs {
		w.mu.Unlock()
		return nil, errors.New("bootstrap mode already started")
	}
	// SMURF TODO: setup wifi hotspot + iptables

	log.Debug("startBootstrap 3")

	// start portal with ssid list and known connections
	w.cp = portal.NewPortal()
	w.cp.Run()
	log.Debug("startBootstrap 4")
	w.state.setBootstrap(true)
	w.mu.Unlock()
	log.Debug("startBootstrap 5")

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

	settingsChan := make(chan wifiSettings)
	w.workers.Add(1)
	go func() {
		log.Debug("bs loop 1")
		defer w.workers.Done()
		defer close(settingsChan)
		for {
			log.Debug("bs loop 2")
			// loop waiting for input
			w.mu.Lock()
			if w.cp == nil {
				log.Debug("bs loop 3")
				w.mu.Unlock()
				break
			}
			log.Debug("bs loop 4")
			ssid, psk, ok := w.cp.GetUserInput()
			if ok {
				log.Debug("bs loop 5")
				log.Debugf("send chan: %+v", settingsChan)
				settingsChan <- wifiSettings{ssid: ssid, psk: psk}
				w.mu.Unlock()
				break
			}
			log.Debug("bs loop 6")
			var knownSSIDs []string
			for k := range w.knownSSIDs {
				knownSSIDs = append(knownSSIDs, k)
			}
			log.Debug("bs loop 7")
			w.cp.SetData(w.visibleSSIDs, knownSSIDs, prevErr)

			// end loop
			w.mu.Unlock()
			log.Debug("bs loop 8")
			time.Sleep(time.Second)
		}
	}()
	log.Debug("startBootstrap 6")

	return settingsChan, nil
}


func (w *NMWrapper) stopBootstrap() error {
	bs, _ := w.state.getBootstrap()
	if !bs {
		return errors.New("bootstrap mode not yet started")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.state.setBootstrap(false)
	err := w.cp.Stop()
	w.cp = nil

	// SMURF TODO: teardown wifi + iptables

	return err
}


func (w *NMWrapper) Close() {
	bs, _ := w.state.getBootstrap()

	if bs {
		err := w.stopBootstrap()
		if err != nil {
			fmt.Println(err)
		}
	}
	w.workers.Wait()
}

func (w *NMWrapper) AddOrUpdateConnection(ssid, psk string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	var err error
	newConn, ok := w.knownSSIDs[ssid]
	if !ok {
		newConn, err = w.settings.AddConnection(getSettingsWifi(connIDPrefix + ssid, ssid, psk))
		if err != nil {
			return err
		}
		w.knownSSIDs[ssid] = newConn
	}
	return newConn.Update(getSettingsWifi(connIDPrefix + ssid, ssid, psk))
}


func setupExitSignalHandling() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 16)
	activeBackgroundWorkers.Add(1)
	go func() {
		defer activeBackgroundWorkers.Done()
		defer cancel()
		for {
			var sig os.Signal
			if ctx.Err() != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			case sig = <-sigChan:
			}

			switch sig {
			// things we exit for
			case os.Interrupt:
				fallthrough
			case syscall.SIGQUIT:
				fallthrough
			case syscall.SIGABRT:
				fallthrough
			case syscall.SIGTERM:
				log.Info("exiting")
				signal.Ignore(os.Interrupt, syscall.SIGTERM, syscall.SIGABRT) // keeping SIGQUIT for stack trace debugging
				return

			// this will eventually be handled elsewhere as a restart, not exit
			case syscall.SIGHUP:

			// ignore SIGURG entirely, it's used for real-time scheduling notifications
			case syscall.SIGURG:

			// log everything else
			default:
				log.Debugw("received unknown signal", "signal", sig)
			}
		}
	}()

	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGABRT)
	return ctx
}