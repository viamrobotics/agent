package provisioning

// This file includes functions used only once during startup in NewNMWrapper()

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"time"

	gnm "github.com/Otterverse/gonetworkmanager/v2"
	errw "github.com/pkg/errors"
)

func (w *Provisioning) writeDNSMasq() error {
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

func (w *Provisioning) testConnCheck() error {
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

func (w *Provisioning) writeConnCheck() error {
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

// must be run inside dataMu lock.
func (w *Provisioning) initDevices() error {
	devices, err := w.nm.GetDevices()
	if err != nil {
		return err
	}

	for _, device := range devices {
		devType, err := device.GetPropertyDeviceType()
		if err != nil {
			return err
		}

		//nolint:exhaustive
		switch devType {
		case gnm.NmDeviceTypeEthernet:
			ethDev, ok := device.(gnm.DeviceWired)
			if !ok {
				return errors.New("cannot cast to wired device")
			}
			ifName, err := ethDev.GetPropertyInterface()
			if err != nil {
				return err
			}
			w.netState.SetEthDevice(ifName, ethDev)
		case gnm.NmDeviceTypeWifi:
			wifiDev, ok := device.(gnm.DeviceWireless)
			if !ok {
				return errors.New("cannot cast to wifi device")
			}
			ifName, err := wifiDev.GetPropertyInterface()
			if err != nil {
				return err
			}
			w.netState.SetWifiDevice(ifName, wifiDev)

			if w.cfg.HotspotInterface == "" || ifName == w.cfg.HotspotInterface {
				w.cfg.HotspotInterface = ifName
				w.logger.Infof("Using %s for hotspot/provisioning, will actively manage wifi only on this device.", ifName)
			}
		default:
			continue
		}

		if err := device.SetPropertyAutoConnect(true); err != nil {
			return err
		}
	}

	if w.cfg.HotspotInterface == "" {
		return errors.New("cannot find wifi device for provisioning/hotspot")
	}

	return nil
}

func (w *Provisioning) enableWifi(ctx context.Context) error {
	if err := w.nm.SetPropertyWirelessEnabled(true); err != nil {
		return err
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	for {
		if !w.mainLoopHealth.Sleep(timeoutCtx, time.Second) {
			return errw.Wrap(timeoutCtx.Err(), "enabling wifi")
		}
		enabled, err := w.nm.GetPropertyWirelessEnabled()
		if err != nil {
			return err
		}
		if enabled {
			return nil
		}
	}
}
