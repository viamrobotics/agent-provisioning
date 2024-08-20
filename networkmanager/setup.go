package networkmanager

// This file includes functions used only once during startup in NewNMWrapper()

import (
	"bytes"
	"errors"
	"io/fs"
	"os"

	gnm "github.com/Otterverse/gonetworkmanager/v2"
	errw "github.com/pkg/errors"
)

func (w *NMWrapper) writeDNSMasq() error {
	DNSMasqContents := DNSMasqContentsRedirect
	if w.cfg.DisableDNSRedirect {
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
		if devType == gnm.NmDeviceTypeEthernet || devType == gnm.NmDeviceTypeWifi {
			if err := device.SetPropertyAutoConnect(true); err != nil {
				return err
			}
		}

		if devType == gnm.NmDeviceTypeWifi && w.dev == nil {
			wifiDev, ok := device.(gnm.DeviceWireless)
			if ok {
				ifName, err := wifiDev.GetPropertyInterface()
				if err != nil {
					return err
				}
				if w.hotspotInterface == "" || ifName == w.cfg.HotspotInterface {
					w.hotspotInterface = ifName
					w.dev = wifiDev
					w.logger.Info("Using %s for hotspot/provisioning, will actively manage wifi only on this device.", ifName)
				}
			}
		}
	}

	if w.dev != nil {
		return nil
	}

	return errors.New("cannot find wifi device for provisioning/hotspot")
}
