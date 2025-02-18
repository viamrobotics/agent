package networking

// This file includes functions used only once during startup in NewNMWrapper()

import (
	"context"
	"errors"
	"time"

	gnm "github.com/Otterverse/gonetworkmanager/v2"
	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/utils"
)

var (
	ErrNM = errw.New("NetworkManager does not appear to be responding as expected. " +
		"Please ensure NetworkManger >= v1.30 is installed and enabled. Disabling networking until next restart.")
	ErrNoWifi = errw.New("No WiFi devices available. Disabling networking until next restart.")
)

func (w *Networking) writeDNSMasq() error {
	DNSMasqContents := DNSMasqContentsRedirect
	if w.cfg.DisableCaptivePortalRedirect {
		DNSMasqContents = DNSMasqContentsSetupOnly
	}

	_, err := utils.WriteFileIfNew(DNSMasqFilepath, []byte(DNSMasqContents))
	return err
}

func (w *Networking) testConnCheck() error {
	connCheckEnabled, err := w.nm.GetPropertyConnectivityCheckEnabled()
	if err != nil {
		return errw.Wrap(err, "getting NetworkManager connectivity check state")
	}

	if !connCheckEnabled {
		hasConnCheck, err := w.nm.GetPropertyConnectivityCheckAvailable()
		if err != nil {
			return errw.Wrap(err, "getting NetworkManager connectivity check configuration")
		}

		if !hasConnCheck {
			if err := w.writeConnCheck(); err != nil {
				return (errw.Wrap(err, "writing NetworkManager connectivity check configuration"))
			}
			if err := w.nm.Reload(0); err != nil {
				return (errw.Wrap(err, "reloading NetworkManager"))
			}

			hasConnCheck, err = w.nm.GetPropertyConnectivityCheckAvailable()
			if err != nil {
				return errw.Wrap(err, "getting NetworkManager connectivity check configuration")
			}
			if !hasConnCheck {
				return errors.New("configuring NetworkManager connectivity check")
			}
		}

		connCheckEnabled, err = w.nm.GetPropertyConnectivityCheckEnabled()
		if err != nil {
			return errw.Wrap(err, "getting NetworkManager connectivity check state")
		}

		if !connCheckEnabled {
			return ErrConnCheckDisabled
		}
	}
	return nil
}

func (w *Networking) writeConnCheck() error {
	_, err := utils.WriteFileIfNew(ConnCheckFilepath, []byte(ConnCheckContents))
	return err
}

// must be run inside dataMu lock.
func (w *Networking) initDevices() error {
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
				w.netState.SetHotspotInterface(ifName)
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
		return ErrNoWifi
	}

	return nil
}

func (w *Networking) enableWifi(ctx context.Context) error {
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
