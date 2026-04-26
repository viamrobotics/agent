package networking

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	dbus "github.com/godbus/dbus/v5"
	"github.com/google/uuid"
	errw "github.com/pkg/errors"
	"go.viam.com/rdk/logging"
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

// bleState is the BLE advertising lifecycle.
type bleState int32

const (
	bleOff      bleState = iota // not started, or cleanly stopped
	bleStarting                 // partial init in progress, Start() not yet succeeded
	bleRunning                  // Start() succeeded, advertising
)

func (s bleState) String() string {
	switch s {
	case bleOff:
		return "off"
	case bleStarting:
		return "starting"
	case bleRunning:
		return "running"
	default:
		return fmt.Sprintf("bleState(%d)", int32(s))
	}
}

// bleTracker couples BLE state and advertisement so they're always updated together.
type bleTracker struct {
	state atomic.Int32             // holds a bleState
	adv   *bluetooth.Advertisement // only accessed from bleLoop
}

func (bt *bleTracker) getState() bleState {
	return bleState(bt.state.Load())
}

func (bt *bleTracker) setStarting(logger logging.Logger) {
	if prev := bt.getState(); prev == bleRunning {
		logger.Warnf("unexpected BLE transition: starting from %s", prev)
	}
	bt.state.Store(int32(bleStarting))
}

// startAdvAndSetRunning calls adv.Start() and transitions to bleRunning on success.
func (bt *bleTracker) startAdvAndSetRunning() error {
	if bt.adv == nil {
		return errors.New("bug: cannot start with nil advertisement")
	}
	if err := bt.adv.Start(); err != nil {
		return err
	}
	bt.state.Store(int32(bleRunning))
	return nil
}

// clearAndSetOff stops the advertisement (if non-nil), nils it, and transitions to bleOff.
func (bt *bleTracker) clearAndSetOff(logger logging.Logger) {
	if bt.adv != nil {
		if err := bt.adv.Stop(); err != nil && err.Error() != btErrAdvNotStarted {
			logger.Warnf("BLE advertisement stop failed during cleanup: %v", err)
		}
		bt.adv = nil
	}
	bt.state.Store(int32(bleOff))
}

// startProvisioningBluetooth starts BLE advertising. On any error it rolls back to bleOff.
// Must only be called from bleLoop.
func (n *Subsystem) startProvisioningBluetooth(ctx context.Context) error {
	if !n.bluetoothEnabled() {
		return nil
	}
	if n.ble.getState() != bleOff {
		return errors.New("invalid request, advertising already active")
	}
	n.ble.setStarting(n.logger)

	if err := n.ensureBluetoothConfiguration(ctx); err != nil {
		n.ble.clearAndSetOff(n.logger)
		return err
	}

	if err := n.checkBluetoothdVersion(ctx); err != nil {
		n.ble.clearAndSetOff(n.logger)
		return err
	}

	// initializeBluetoothService may fail after AddService but before btAdv is assigned.
	if err := n.initializeBluetoothService(ctx, n.Config().HotspotSSID, n.btChar.initCharacteristics(ctx)); err != nil {
		n.cleanupPartialBluetooth()
		return fmt.Errorf("failed to initialize bluetooth service: %w", err)
	}

	// Update bluetooth read-only characteristics
	if err := n.btChar.updateStatus(n.connState.getConfigured(), n.connState.getConnected() || n.connState.getOnline()); err != nil {
		n.logger.Warnf("failed to write initial BLE status characteristic: %v", err)
	}
	if err := n.btChar.updateNetworks(n.getVisibleNetworks()); err != nil {
		n.logger.Warnf("failed to write initial BLE networks characteristic: %v", err)
	}

	if err := n.enablePairing(n.Config().HotspotSSID); err != nil {
		n.cleanupPartialBluetooth()
		return err
	}

	if err := n.ble.startAdvAndSetRunning(); err != nil {
		n.cleanupPartialBluetooth()
		return fmt.Errorf("failed to start advertising: %w", err)
	}
	return nil
}

// cleanupPartialBluetooth resets in-process BLE state and best-effort tears down
// pairing + gatt. Idempotent in our process; bluez may retain its own state across calls.
func (n *Subsystem) cleanupPartialBluetooth() {
	n.ble.clearAndSetOff(n.logger)
	if err := n.disablePairing(); err != nil {
		n.logger.Warnf("BLE pairing disable failed during rollback: %v", err)
	}
	if err := n.removeServices(); err != nil {
		n.logger.Debugf("BLE gatt service removal failed during rollback: %v", err)
	}
}

// stopProvisioningBluetooth stops BLE advertising and tears down the gatt service.
// Must only be called from bleLoop.
func (n *Subsystem) stopProvisioningBluetooth() error {
	state := n.ble.getState()
	switch state {
	case bleOff:
		n.logger.Debug("BLE stop requested but already off")
		return nil
	case bleStarting:
		n.cleanupPartialBluetooth()
		return nil
	case bleRunning:
		n.ble.clearAndSetOff(n.logger)
		if err := n.disablePairing(); err != nil {
			return err
		}
		if err := n.removeServices(); err != nil {
			return err
		}
		n.logger.Debug("BLE advertising stopped")
		return nil
	default:
		return fmt.Errorf("unknown ble state %d", state)
	}
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

	n.ble.adv = adv
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
