package networkmanager

// This file includes functions used for wifi scans.

import (
	"context"
	"strings"
	"time"

	gnm "github.com/Otterverse/gonetworkmanager/v2"
	errw "github.com/pkg/errors"

	provisioning "github.com/viamrobotics/agent-provisioning"
)

func (w *NMWrapper) NetworkScan(ctx context.Context) error {
	w.opMu.Lock()
	defer w.opMu.Unlock()

	wifiDev, ok := w.wifiDevices[w.hotspotInterface]
	if !ok {
		return errw.Errorf("cannot find hotspot interface: %s", w.hotspotInterface)
	}

	prevScan, err := wifiDev.GetPropertyLastScan()
	if err != nil {
		return errw.Wrap(err, "error scanning wifi")
	}

	err = wifiDev.RequestScan()
	if err != nil {
		return errw.Wrap(err, "scanning wifi")
	}

	var lastScan int64
	for {
		lastScan, err = wifiDev.GetPropertyLastScan()
		if err != nil {
			return errw.Wrap(err, "scanning wifi")
		}
		if lastScan > prevScan {
			break
		}
		if !provisioning.HealthySleep(ctx, time.Second) {
			return nil
		}
	}

	wifiList, err := wifiDev.GetAccessPoints()
	if err != nil {
		return errw.Wrap(err, "scanning wifi")
	}

	w.dataMu.Lock()
	defer w.dataMu.Unlock()

	// set "now" to be reusable for consistency
	now := time.Now()
	for _, ap := range wifiList {
		if ctx.Err() != nil {
			return nil
		}
		ssid, err := ap.GetPropertySSID()
		if err != nil {
			w.logger.Warn(errw.Wrap(err, "scanning wifi"))
			continue
		}

		signal, err := ap.GetPropertyStrength()
		if err != nil {
			w.logger.Warn(errw.Wrap(err, "scanning wifi"))
			continue
		}

		apFlags, err := ap.GetPropertyFlags()
		if err != nil {
			w.logger.Warn(errw.Wrap(err, "scanning wifi"))
			continue
		}

		wpaFlags, err := ap.GetPropertyWPAFlags()
		if err != nil {
			w.logger.Warn(errw.Wrap(err, "scanning wifi"))
			continue
		}

		rsnFlags, err := ap.GetPropertyRSNFlags()
		if err != nil {
			w.logger.Warn(errw.Wrap(err, "scanning wifi"))
			continue
		}

		nw, ok := w.networks[ssid]
		if !ok {
			nw = &network{
				netType: NetworkTypeWifi,
				ssid:    ssid,
			}
			w.networks[ssid] = nw
		}

		nw.netType = NetworkTypeWifi
		nw.ssid = ssid
		nw.security = parseWPAFlags(apFlags, wpaFlags, rsnFlags)
		nw.signal = signal
		nw.lastSeen = now

		if nw.firstSeen.IsZero() {
			nw.firstSeen = now
		}
	}

	for _, nw := range w.networks {
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

// updates connections/settings from those known to NetworkManager.
func (w *NMWrapper) updateKnownConnections(ctx context.Context) error {
	conns, err := w.settings.ListConnections()
	if err != nil {
		return err
	}

	highestPriority := make(map[string]int32)
	for _, conn := range conns {
		//nolint:nilerr
		if ctx.Err() != nil {
			return nil
		}
		settings, err := conn.GetSettings()
		if err != nil {
			return err
		}

		netKey, ifName, netType := getKeyIfNameTypeFromSettings(settings)
		if netKey == "" {
			// unknown network type, or broken network
			continue
		}

		_, ok := highestPriority[ifName]
		if !ok {
			highestPriority[ifName] = -999
		}

		// actually record the network
		nw, ok := w.networks[netKey]
		if !ok {
			nw = &network{
				netType:       netType,
				interfaceName: ifName,
			}
			if netType == NetworkTypeWifi {
				nw.ssid = getSSIDFromSettings(settings)
			}
			w.networks[netKey] = nw
		}
		nw.conn = conn
		nw.priority = getPriorityFromSettings(settings)

		if nw.ssid == w.hotspotSSID {
			nw.netType = NetworkTypeHotspot
			nw.isHotspot = true
		} else if nw.priority > highestPriority[ifName] {
			highestPriority[ifName] = nw.priority
			w.primarySSID[ifName] = nw.ssid
		}
	}

	return nil
}

func getPriorityFromSettings(settings gnm.ConnectionSettings) int32 {
	connection, ok := settings["connection"]
	if !ok {
		return 0
	}

	priRaw, ok := connection["autoconnect-priority"]
	if !ok {
		return 0
	}

	priority, ok := priRaw.(int32)
	if !ok {
		return 0
	}
	return priority
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

func getKeyIfNameTypeFromSettings(settings gnm.ConnectionSettings) (string, string, string) {
	_, wired := settings["802-3-ethernet"]
	_, wireless := settings["802-11-wireless"]
	if !wired && !wireless {
		return "", "", ""
	}

	ifName := "any"
	conn, ok := settings["connection"]
	if ok {
		ifKey, ok := conn["interface-name"]
		if ok {
			name, ok := ifKey.(string)
			if ok {
				ifName = name
			}
		}
	}

	if wired {
		return GenNetKey(ifName, ""), ifName, NetworkTypeWired
	}

	if wireless {
		ssid := getSSIDFromSettings(settings)
		if ssid == "" {
			return "", "", ""
		}
		return GenNetKey(ifName, ssid), ifName, NetworkTypeWifi
	}

	return "", "", ""
}
