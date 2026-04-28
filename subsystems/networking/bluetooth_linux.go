package networking

import (
	"context"
	"errors"
	"fmt"

	dbus "github.com/godbus/dbus/v5"
	"github.com/google/uuid"
	errw "github.com/pkg/errors"
	"tinygo.org/x/bluetooth"
)

const (
	BluezDBusService  = "org.bluez"
	BluezAgentManager = "org.bluez.AgentManager1"
	BluezAgent        = "org.bluez.Agent1"
	BluezAgentPath    = "/com/viam/btagent"
	BluezConfigPath   = "/etc/bluetooth/main.conf"
)

// startProvisioningBluetooth should only be called by 'StartProvisioning' (to ensure opMutex is acquired).
func (n *Subsystem) startProvisioningBluetooth(ctx context.Context) error {
	if !n.bluetoothEnabled() {
		return nil
	}
	if n.btAdv != nil {
		return errors.New("invalid request, advertising already active")
	}
	n.btHealthy = false

	if err := n.ensureBluetoothConfiguration(ctx); err != nil {
		n.noBT = true
		return err
	}

	if err := n.checkBluetoothdVersion(ctx); err != nil {
		n.noBT = true
		return err
	}

	// Create a bluetooth service comprised of the above configs.
	if err := n.initializeBluetoothService(ctx, n.Config().HotspotSSID, n.btChar.initCharacteristics(ctx)); err != nil {
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

	// Start advertising the bluetooth service.
	if err := n.btAdv.Start(); err != nil {
		return fmt.Errorf("failed to start advertising: %w", err)
	}
	n.btHealthy = true

	n.logger.Info("Bluetooth provisioning started.")
	return nil
}

// stop stops advertising a bluetooth service which (when enabled) accepts WiFi and Viam cloud config credentials.
func (n *Subsystem) stopProvisioningBluetooth() error {
	if n.btAdv == nil {
		n.logger.Warnf("bluetooth already stopped")
		return nil
	}
	// 'not started' is unexported but comes from here
	// https://github.com/tinygo-org/bluetooth/blob/5c615298c3e4400150c44da3636f3d3b10967e3c/gap_linux.go#L48
	if err := n.btAdv.Stop(); err != nil {
		if err.Error() == "bluetooth: advertisement is not started" {
			n.logger.Warnf("ignoring %q from Stop()", err)
		} else {
			return fmt.Errorf("failed to stop BT advertising: %w", err)
		}
	}
	n.btAdv = nil

	if err := n.disablePairing(); err != nil {
		return err
	}

	n.removeServices()

	n.btHealthy = false
	n.logger.Debug("Stopped advertising bluetooth service.")
	return nil
}

// initializeBluetoothService performs low-level system configuration to enable bluetooth advertisement.
func (n *Subsystem) initializeBluetoothService(
	ctx context.Context, deviceName string, characteristics []bluetooth.CharacteristicConfig,
) error {
	if err := rfkillUnblock(ctx); err != nil {
		n.logger.Warnw("Failed to unblock bluetooth with rfkill; bluetooth initialization will continue but may fail", "err", err)
	}

	serviceUUID := bluetooth.NewUUID(uuid.NewSHA1(uuid.MustParse(uuidNamespace), []byte(serviceNameKey)))

	adapter := bluetooth.DefaultAdapter
	if err := adapter.Enable(); err != nil {
		return fmt.Errorf("failed to enable bluetooth adapter: %w", err)
	}
	svc := &bluetooth.Service{UUID: serviceUUID, Characteristics: characteristics}
	if err := adapter.AddService(svc); err != nil {
		return fmt.Errorf("unable to add bluetooth service to default adapter: %w", err)
	}
	n.bleService = svc

	adv := adapter.DefaultAdvertisement()
	opts := bluetooth.AdvertisementOptions{
		LocalName:    deviceName,
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

func (n *Subsystem) removeServices() {
	if n.bleService == nil {
		return
	}
	defer func() { n.bleService = nil }()

	err := bluetooth.DefaultAdapter.RemoveService(n.bleService)
	if err == nil {
		return
	}
	dErr := &dbus.Error{}
	if errors.As(err, dErr) && dErr.Name == "org.bluez.Error.DoesNotExist" {
		// BlueZ already cleaned up the service (e.g. adapter power-cycled). Nothing to do.
		return
	}
	n.logger.Errorf(
		"failed to unregister gatt service in bluez; orphaned service will persist until agent restart: %v", err,
	)
}

func (n *Subsystem) bluetoothEnabled() bool {
	n.dataMu.RLock()
	noBT := n.noBT
	n.dataMu.RUnlock()
	return !noBT && !n.Config().DisableBTProvisioning.Get()
}
