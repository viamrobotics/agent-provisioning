package main

import (
	"context"
	"fmt"
	"os"
	"time"

	gnm "github.com/Wifx/gonetworkmanager/v2"
	"github.com/google/uuid"

	"github.com/viamrobotics/agent-network/portal"
)

func main() {
	nm, err := gnm.NewNetworkManager()
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	dev, err := getWifiDev(nm)
	if err != nil {
		fmt.Println(err.Error(), dev)
		os.Exit(1)	
	}


	ssid, psk, err := bootstrap(nil)

	fmt.Println("SMURF BOOTSTRAP", ssid, psk, err)

	// start monitoring loop
	for {
		// check if online, record result

		// if not online for X, start bootstrap

		// bootstrap returns when good
		break
	}



	// liveConn, err := nm.AddAndActivateConnection(getSettingsHotspot(), dev)
	// if err != nil {
	// 	fmt.Println(err.Error())
	// 	os.Exit(1)	
	// }

	// fmt.Printf("LIVE: %+v\n", liveConn)


	// nmSettings, _ := gnm.NewSettings()
	// connections, _ := nmSettings.ListConnections()

	// for _, conn := range connections {
	// 	settings, _ := conn.GetSettings()
	// 	fmt.Println(settings)
	// }


	os.Exit(0)
}

// bootstrap put the wifi in hotspot mode and starts a captive portal
func bootstrap(prevError error) (string, string, error){
	// scan wifi for ssids

	// get known/saved connections from NM

	ssids := []string{"smurfKnown"}
	savedSSIDs := []string{"smurfSaved"}
	prevErr := error(nil)

	// setup wifi hotspot + iptables

	// start portal with ssid list and known connections
	cp := portal.NewPortal(ssids, savedSSIDs, prevErr)

	ctxTimeout, cancelFunc := context.WithTimeout(context.Background(), time.Minute)
	defer cancelFunc()

	err := cp.Run(ctxTimeout)
	if err != nil {
		fmt.Println("SMURF ERROR", err)
	}

	return cp.GetSettings()
}




func getWifiDev(nm gnm.NetworkManager) (gnm.Device, error) {
	devices, err := nm.GetPropertyAllDevices()
	if err != nil {
		return nil, err
	}

	for _, device := range devices {
		devType, err := device.GetPropertyDeviceType()
		if err != nil {
			fmt.Printf("Error: %s", err.Error())
		}
		if devType == gnm.NmDeviceTypeWifi {
			return device, nil
		}
	}
	return nil, fmt.Errorf("cannot find wifi device")
}

func getSettingsWifi(ssid, psk string) (gnm.ConnectionSettings) {
	settings := gnm.ConnectionSettings{
		"connection": map[string]interface{}{
			"id": "TestWifi",
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


func getSettingsHotspot() (gnm.ConnectionSettings) {
	hostname, _ := os.Hostname()

	settings := gnm.ConnectionSettings{
		"connection": map[string]interface{}{
			"id": "TestWifi",
			"uuid": uuid.New().String(),
			"type": "802-11-wireless",
		},
		"802-11-wireless": map[string]interface{}{
			"mode": "ap",
			"ssid": []byte("ViamRobot-" + hostname),
		},
		"802-11-wireless-security": map[string]interface{}{
			"key-mgmt": "wpa-psk",
			"psk": "Viam1234",
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