package networking

import (
	"context"
	"errors"
	"fmt"
	"time"

	dbus "github.com/godbus/dbus/v5"
	"github.com/google/uuid"
	errw "github.com/pkg/errors"
	"tinygo.org/x/bluetooth"
)

const (
	BluezDBusService  = "org.bluez"
	BluezAgentPath    = "/custom/agent"
	BluezAgentManager = "org.bluez.AgentManager1"
	BluezAgent        = "org.bluez.Agent1"
)

// startProvisioningBluetooth should only be called by 'StartProvisioning' (to ensure opMutex is acquired).
func (n *Networking) startProvisioningBluetooth(ctx context.Context) error {
	if n.Config().DisableBTProvisioning || n.noBT {
		return nil
	}
	if n.btAdv != nil {
		return errors.New("invalid request, advertising already active")
	}

	// Create a bluetooth service comprised of the above configs.
	if err := n.initializeBluetoothService(n.btChar.initCharacteristics()); err != nil {
		n.noBT = true
		return fmt.Errorf("failed to initialize bluetooth service: %w", err)
	}

	// Update bluetooth read-only characteristics
	if err := n.btChar.updateStatus(n.connState.getConfigured(), n.connState.getConnected() || n.connState.getOnline()); err != nil {
		n.logger.Warn("could not update BT status characteristic")
	}
	if err := n.btChar.updateNetworks(n.getVisibleNetworks()); err != nil {
		n.logger.Warn("could not update BT networks characteristic")
	}

	if err := n.enablePairing(n.Config().HotspotSSID); err != nil {
		return err
	}

	// Start the loop that monitors for BT writes.
	n.btChar.startBTLoop(ctx)

	// Start advertising the bluetooth service.
	if err := n.btAdv.Start(); err != nil {
		return fmt.Errorf("failed to start advertising: %w", err)
	}

	n.logger.Info("Bluetooth provisioning started.")
	return nil
}

// stop stops advertising a bluetooth service which (when enabled) accepts WiFi and Viam cloud config credentials.
func (n *Networking) stopProvisioningBluetooth() error {
	if n.btAdv == nil {
		n.logger.Warnf("bluetooth already stopped")
		return nil
	}
	if err := n.btAdv.Stop(); err != nil {
		return fmt.Errorf("failed to stop BT advertising: %w", err)
	}
	n.btAdv = nil
	n.btChar.stopBTLoop()
	if err := n.disablePairing(); err != nil {
		return err
	}

	n.logger.Debug("Stopped advertising bluetooth service.")
	return nil
}

// initializeBluetoothService performs low-level system configuration to enable bluetooth advertisement.
func (n *Networking) initializeBluetoothService(characteristics []bluetooth.CharacteristicConfig) error {
	serviceUUID := bluetooth.NewUUID(uuid.NewSHA1(uuid.MustParse(uuidNamespace), []byte(serviceNameKey)))

	adapter := bluetooth.DefaultAdapter
	if err := adapter.Enable(); err != nil {
		return fmt.Errorf("failed to enable bluetooth adapter: %w", err)
	}
	if err := adapter.AddService(&bluetooth.Service{UUID: serviceUUID, Characteristics: characteristics}); err != nil {
		return fmt.Errorf("unable to add bluetooth service to default adapter: %w", err)
	}
	adv := adapter.DefaultAdvertisement()
	opts := bluetooth.AdvertisementOptions{
		ServiceUUIDs: []bluetooth.UUID{serviceUUID},
	}
	if err := adv.Configure(opts); err != nil {
		return fmt.Errorf("failed to configure default advertisement: %w", err)
	}
	if err := n.btChar.initCrypto(); err != nil {
		return err
	}
	if err := n.btChar.initDevInfo(n.Config()); err != nil {
		return err
	}

	n.btAdv = adv
	n.logger.Debugf("Bluetooth service UUID: %s.", serviceUUID.String())
	return nil
}

func (n *Networking) enablePairing(deviceName string) error {
	conn, adapter, err := getBluetoothDBus()
	if err != nil {
		return err
	}

	err = adapter.SetProperty("org.bluez.Adapter1.Alias", dbus.MakeVariant(deviceName))
	if err != nil {
		return errw.Wrap(err, "setting bluetooth alias")
	}

	n.logger.Debug("setting bluetooth to discoverable")
	err = adapter.SetProperty("org.bluez.Adapter1.Discoverable", dbus.MakeVariant(true))
	if err != nil {
		return errw.Wrap(err, "enabling bluetooth discovery")
	}

	discoveryTimeout := uint32(time.Duration(n.Config().RetryConnectionTimeoutMinutes * 2).Seconds())
	err = adapter.SetProperty("org.bluez.Adapter1.DiscoverableTimeout", dbus.MakeVariant(discoveryTimeout))
	if err != nil {
		return errw.Wrap(err, "adjusting discovery timeout")
	}

	if err := conn.Export(nil, BluezAgentPath, BluezAgent); err != nil {
		return errw.Wrap(err, "exporting custom agent object")
	}

	obj := conn.Object(BluezDBusService, "/org/bluez")
	call := obj.Call("org.bluez.AgentManager1.RegisterAgent", 0, dbus.ObjectPath(BluezAgentPath), "NoInputNoOutput")
	if err := call.Err; err != nil {
		return errw.Wrap(err, "registering custom agent")
	}

	n.logger.Debug("bluetooth pairing enabled")
	return nil
}

func (n *Networking) disablePairing() error {
	conn, adapter, err := getBluetoothDBus()
	if err != nil {
		return err
	}

	obj := conn.Object(BluezDBusService, "/org/bluez")
	call := obj.Call("org.bluez.AgentManager1.UnregisterAgent", 0, dbus.ObjectPath(BluezAgentPath))
	if err := call.Err; err != nil {
		n.logger.Errorf("failed to unregister a bluez agent: %v", err)
	}

	n.logger.Debug("setting bluetooth to NOT discoverable")
	err = adapter.SetProperty("org.bluez.Adapter1.Discoverable", dbus.MakeVariant(false))
	if err != nil {
		return errw.Wrap(err, "disabling bluetooth discovery")
	}
	n.logger.Debug("bluetooth pairing disabled")
	return nil
}

func getBluetoothDBus() (*dbus.Conn, dbus.BusObject, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, nil, errw.Wrap(err, "failed to connect to system DBus")
	}
	hci0Adapter := conn.Object("org.bluez", dbus.ObjectPath("/org/bluez/hci0"))
	// Use "Address" property to check if adapter hci0 is even available.
	_, err = hci0Adapter.GetProperty("org.bluez.Adapter1.Address")
	if err != nil {
		dErr := &dbus.Error{}
		if errors.As(err, dErr) && dErr.Name == "org.freedesktop.DBus.Error.UnknownObject" {
			return nil, nil, errw.Errorf("bluetooth adapter %s does not exist", hci0Adapter.Path())
		}
		return nil, nil, errw.Wrap(err, "getting bluetooth adapter")
	}
	return conn, hci0Adapter, nil
}
