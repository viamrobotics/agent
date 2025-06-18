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
func (n *Networking) startProvisioningBluetooth(ctx context.Context) error {
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
	if err := n.initializeBluetoothService(n.Config().HotspotSSID, n.btChar.initCharacteristics(ctx)); err != nil {
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

	// TODO RSDK-10815: Enable pairing and tethering

	// Start advertising the bluetooth service.
	if err := n.btAdv.Start(); err != nil {
		return fmt.Errorf("failed to start advertising: %w", err)
	}
	n.btHealthy = true

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

	// TODO RSDK-10815: Enable pairing and tethering

	if err := n.removeServices(); err != nil {
		return err
	}

	n.btHealthy = false
	n.logger.Debug("Stopped advertising bluetooth service.")
	return nil
}

// initializeBluetoothService performs low-level system configuration to enable bluetooth advertisement.
func (n *Networking) initializeBluetoothService(deviceName string, characteristics []bluetooth.CharacteristicConfig) error {
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

func (n *Networking) removeServices() error {
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
		err := adapter.Call("org.bluez.GattManager1.UnregisterApplication", 0, path).Err
		if err == nil {
			n.logger.Debugf("removed gatt service %s", path)
			ok = true
		}
	}

	if ok {
		return nil
	}
	return errors.New("could not find previous gatt service to remove")
}

func (n *Networking) bluetoothEnabled() bool {
	n.dataMu.Lock()
	noBT := n.noBT
	n.dataMu.Unlock()
	return !noBT && !n.Config().DisableBTProvisioning.Get()
}
