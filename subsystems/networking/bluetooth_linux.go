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

	// Unexported error from tinygo/bluetooth when Stop() is called on an advertisement that hasn't started.
	// https://github.com/tinygo-org/bluetooth/blob/5c615298c3e4400150c44da3636f3d3b10967e3c/gap_linux.go#L48
	btErrAdvNotStarted = "bluetooth: advertisement is not started"
)

// bleState is the BLE advertising lifecycle. Atomic so HealthCheck can read without a mutex.
type bleState int32

const (
	bleOff      bleState = iota // not started, or cleanly stopped
	bleStarting                 // partial init in progress, Start() not yet succeeded
	bleRunning                  // Start() succeeded, advertising
)

func (n *Subsystem) getBleState() bleState {
	return bleState(n.bleState.Load())
}

func (n *Subsystem) setBleState(s bleState) {
	n.bleState.Store(int32(s))
}

// startProvisioningBluetooth starts BLE advertising. On any error it rolls back to bleOff.
// Must only be called from bleLoop.
func (n *Subsystem) startProvisioningBluetooth(ctx context.Context) error {
	if !n.bluetoothEnabled() {
		return nil
	}
	if n.getBleState() != bleOff {
		return errors.New("invalid request, advertising already active")
	}
	n.setBleState(bleStarting)

	if err := n.ensureBluetoothConfiguration(ctx); err != nil {
		n.setBleState(bleOff)
		return err
	}

	if err := n.checkBluetoothdVersion(ctx); err != nil {
		n.setBleState(bleOff)
		return err
	}

	// initializeBluetoothService may fail after AddService but before btAdv is assigned.
	if err := n.initializeBluetoothService(ctx, n.Config().HotspotSSID, n.btChar.initCharacteristics(ctx)); err != nil {
		n.cleanupPartialBluetooth()
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
		n.cleanupPartialBluetooth()
		return err
	}

	// Start advertising the bluetooth service.
	if err := n.btAdv.Start(); err != nil {
		n.cleanupPartialBluetooth()
		return fmt.Errorf("failed to start advertising: %w", err)
	}
	n.setBleState(bleRunning)

	n.logger.Info("Bluetooth provisioning started.")
	return nil
}

// cleanupPartialBluetooth is idempotent BLE teardown; transitions to bleOff.
func (n *Subsystem) cleanupPartialBluetooth() {
	if n.btAdv != nil {
		if err := n.btAdv.Stop(); err != nil && err.Error() != btErrAdvNotStarted {
			n.logger.Warnw("error stopping BT advertising during rollback", "err", err)
		}
		n.btAdv = nil
	}
	if err := n.disablePairing(); err != nil {
		n.logger.Warnw("error disabling BT pairing during rollback", "err", err)
	}
	if err := n.removeServices(); err != nil {
		n.logger.Debugw("no gatt services to remove during rollback", "err", err)
	}
	n.setBleState(bleOff)
}

// stopProvisioningBluetooth stops BLE advertising and tears down the gatt service.
// Must only be called from bleLoop.
func (n *Subsystem) stopProvisioningBluetooth() error {
	currentState := n.getBleState()
	if currentState == bleOff {
		n.logger.Warnf("bluetooth already stopped")
		return nil
	}
	if currentState == bleStarting {
		n.cleanupPartialBluetooth()
		return nil
	}
	if n.btAdv != nil {
		if err := n.btAdv.Stop(); err != nil {
			if err.Error() == btErrAdvNotStarted {
				n.logger.Warnf("ignoring %q from Stop()", err)
			} else {
				// Full cleanup so bleState doesn't get stuck at bleRunning with btAdv nil.
				n.cleanupPartialBluetooth()
				return fmt.Errorf("failed to stop BT advertising: %w", err)
			}
		}
		n.btAdv = nil
	}

	if err := n.disablePairing(); err != nil {
		n.cleanupPartialBluetooth()
		return err
	}

	if err := n.removeServices(); err != nil {
		n.cleanupPartialBluetooth()
		return err
	}

	n.setBleState(bleOff)
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
	if err := adapter.AddService(&bluetooth.Service{UUID: serviceUUID, Characteristics: characteristics}); err != nil {
		return fmt.Errorf("unable to add bluetooth service to default adapter: %w", err)
	}

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

func (n *Subsystem) removeServices() error {
	_, adapter, err := getBluetoothDBus()
	if err != nil {
		return err
	}

	// TODO(APP-8081) tinygo/bluetooth only has a AddService() method, no RemoveService() and doesn't expose the service path
	// As it sequentially names them, we'll just iterate over 10000 of them to make sure we reasonably have cleaned up
	// This takes about one realtime second on a pi5, so not THAT expensive
	var ok bool
	for id := range 10000 {
		path := dbus.ObjectPath(fmt.Sprintf("/org/tinygo/bluetooth/service%d", id))
		if adapter.Call("org.bluez.GattManager1.UnregisterApplication", 0, path).Err == nil {
			n.logger.Debugf("removed gatt service %s", path)
			ok = true
		}
	}

	if ok {
		return nil
	}
	return errors.New("could not find previous gatt service to remove")
}

func (n *Subsystem) bluetoothEnabled() bool {
	return !n.Config().DisableBTProvisioning.Get()
}
