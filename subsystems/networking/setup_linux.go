package networking

// This file includes functions used only once during startup in NewNMWrapper()

import (
	"context"
	"errors"
	"time"

	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/utils"
	gnm "github.com/viamrobotics/gonetworkmanager/v2"
)

var (
	ErrNM = errw.New("NetworkManager does not appear to be responding as expected. " +
		"Please ensure NetworkManger >= v1.30 is installed and enabled. Disabling networking until next restart.")
	ErrNoWifi = errw.New("No WiFi devices available. Disabling networking until next restart.")
)

func (n *Subsystem) writeDNSMasq() error {
	DNSMasqContents := DNSMasqContentsRedirect
	if n.cfg.DisableCaptivePortalRedirect.Get() {
		DNSMasqContents = DNSMasqContentsSetupOnly
	}

	_, err := utils.WriteFileIfNew(DNSMasqFilepath, []byte(DNSMasqContents))
	return err
}

func (n *Subsystem) testConnCheck() error {
	connCheckEnabled, err := n.nm.GetPropertyConnectivityCheckEnabled()
	if err != nil {
		return errw.Wrap(err, "getting NetworkManager connectivity check state")
	}

	if !connCheckEnabled {
		hasConnCheck, err := n.nm.GetPropertyConnectivityCheckAvailable()
		if err != nil {
			return errw.Wrap(err, "getting NetworkManager connectivity check configuration")
		}

		if !hasConnCheck {
			if err := n.writeConnCheck(); err != nil {
				return (errw.Wrap(err, "writing NetworkManager connectivity check configuration"))
			}
			if err := n.nm.Reload(0); err != nil {
				return (errw.Wrap(err, "reloading NetworkManager"))
			}

			hasConnCheck, err = n.nm.GetPropertyConnectivityCheckAvailable()
			if err != nil {
				return errw.Wrap(err, "getting NetworkManager connectivity check configuration")
			}
			if !hasConnCheck {
				return errors.New("configuring NetworkManager connectivity check")
			}
		}

		connCheckEnabled, err = n.nm.GetPropertyConnectivityCheckEnabled()
		if err != nil {
			return errw.Wrap(err, "getting NetworkManager connectivity check state")
		}

		if !connCheckEnabled {
			return ErrConnCheckDisabled
		}
	}
	return nil
}

func (n *Subsystem) writeConnCheck() error {
	_, err := utils.WriteFileIfNew(ConnCheckFilepath, []byte(ConnCheckContents))
	return err
}

// must be run inside dataMu lock.
func (n *Subsystem) initDevices() error {
	devices, err := n.nm.GetDevices()
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
			n.netState.SetEthDevice(ifName, ethDev)
		case gnm.NmDeviceTypeWifi:
			wifiDev, ok := device.(gnm.DeviceWireless)
			if !ok {
				return errors.New("cannot cast to wifi device")
			}
			ifName, err := wifiDev.GetPropertyInterface()
			if err != nil {
				return err
			}
			n.netState.SetWifiDevice(ifName, wifiDev)

			if n.cfg.HotspotInterface == "" || ifName == n.cfg.HotspotInterface {
				n.cfg.HotspotInterface = ifName
				n.netState.SetHotspotInterface(ifName)
				n.logger.Infof("Using %s for hotspot/provisioning, will actively manage wifi only on this device.", ifName)
			}
		case gnm.NmDeviceTypeBt:
			ifName, err := device.GetPropertyInterface()
			if err != nil {
				return err
			}
			n.netState.SetBTDevice(ifName, device)
		default:
			continue
		}

		if err := device.SetPropertyAutoConnect(true); err != nil {
			return err
		}
	}

	if n.cfg.HotspotInterface == "" {
		return ErrNoWifi
	}

	return nil
}

func (n *Subsystem) enableWifi(ctx context.Context) error {
	if err := n.nm.SetPropertyWirelessEnabled(true); err != nil {
		return err
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	for {
		if !n.mainLoopHealth.Sleep(timeoutCtx, time.Second) {
			return errw.Wrap(timeoutCtx.Err(), "enabling wifi")
		}
		enabled, err := n.nm.GetPropertyWirelessEnabled()
		if err != nil {
			return err
		}
		if enabled {
			return nil
		}
	}
}
