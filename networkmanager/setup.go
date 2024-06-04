package networkmanager

// This file includes functions used only once during startup in NewNMWrapper()

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"

	gnm "github.com/Otterverse/gonetworkmanager/v2"
	errw "github.com/pkg/errors"
)

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
