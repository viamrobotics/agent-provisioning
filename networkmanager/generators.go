package networkmanager

import (
	gnm "github.com/Otterverse/gonetworkmanager/v2"
	"github.com/google/uuid"
)

// This file contains the wifi/hotspot setting generation functions.

func generateWifiSettings(id, ssid, psk string, priority int32) gnm.ConnectionSettings {
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

func generateHotspotSettings(id, ssid, psk string) gnm.ConnectionSettings {
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
