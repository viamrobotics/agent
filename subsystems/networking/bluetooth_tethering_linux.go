package networking

import (
	"fmt"
	"slices"
	"sync"
	"time"

	dbus "github.com/godbus/dbus/v5"
	errw "github.com/pkg/errors"
	"go.viam.com/rdk/logging"
)

var errPairingRejected = &dbus.Error{Name: "org.bluez.Error.Rejected"}

type basicAgent struct {
	mu      sync.Mutex
	conn    *dbus.Conn
	logger  logging.Logger
	trusted []string
}

func (b *basicAgent) Cancel() *dbus.Error {
	b.logger.Debug("SMURF Cancel")
	return nil
}

func (b *basicAgent) DisplayPasskey(devicePath dbus.ObjectPath, passkey, entered uint32) *dbus.Error {
	b.logger.Debugf("SMURF DisplayPasskey %s", passkey)
	return nil
}

func (b *basicAgent) DisplayPinCode(devicePath dbus.ObjectPath, pincode string) *dbus.Error {
	b.logger.Debugf("SMURF DisplayPinCode %s", pincode)
	return nil
}

func (b *basicAgent) RequestConfirmation(devicePath dbus.ObjectPath, passkey uint32) *dbus.Error {
	b.logger.Debug("SMURF RequestConfirmation")
	return b.RequestAuthorization(devicePath)
}

func (b *basicAgent) RequestAuthorization(devicePath dbus.ObjectPath) *dbus.Error {
	b.logger.Debugf("SMURF RequestAuthorization %+v", devicePath)
	conn, _, err := getBluetoothDBus()
	if err != nil {
		b.logger.Error(err)
		return errPairingRejected
	}

	remoteDev := conn.Object(BluezDBusService, devicePath)

	bdaddr, err := remoteDev.GetProperty("org.bluez.Device1.Address")
	if err != nil {
		b.logger.Error(err)
		return errPairingRejected
	}

	// bdaddrStr := strings.Trim(bdaddr.String(), "\"")
	bdaddrStr := bdaddr.Value().(string)

	b.mu.Lock()
	defer b.mu.Unlock()

	b.logger.Infof("Bluetooth pairing request from: %s", bdaddrStr)
	b.logger.Warnf("SMURF equal:%t, (%s), (%s)", bdaddrStr == b.trusted[0], bdaddrStr, b.trusted[0])

	if !slices.Contains(b.trusted, bdaddrStr) {
		b.logger.Errorf("Bluetooth device pairing rejected for %s, device address must be added via provisioning first.", bdaddrStr)
		return errPairingRejected
	}

	if err := remoteDev.SetProperty("org.bluez.Device1.Trusted", true); err != nil {
		b.logger.Error(errw.Wrapf(err, "trusting bluetooth device %s", bdaddrStr))
	} else {
		b.logger.Infof("Bluetooth device trusted: %s", bdaddrStr)
	}

	b.logger.Warnf("Bluetooth device paired: %s", bdaddrStr)

	go func() {
		b.logger.Warn("SMURF1")

		var i int
		for {
			i++
			ret, err := remoteDev.GetProperty("org.bluez.Device1.Paired")
			if err != nil {
				b.logger.Warn(errw.Wrapf(err, "cannot get paired status for bluetooth device %s", bdaddrStr))
			}
			if ret.Value().(bool) || i > 30 {
				break
			}
			b.logger.Warnf("SMURF Value: %+v", ret.Value())
			time.Sleep(time.Second * 1)
		}
		b.logger.Warn("SMURF2")
		call := remoteDev.Call("org.bluez.Device1.ConnectProfile", 0, "00001115-0000-1000-8000-00805f9b34fb")
		b.logger.Warn("SMURF3")
		if err := call.Err; err != nil {
			b.logger.Error(errw.Wrapf(err, "connecting bluetooth device %s", bdaddrStr))
		}

		b.logger.Infof("Connected bluetooth device for tethering: %s", bdaddrStr)
	}()

	return nil
}

func (n *Networking) enablePairing(deviceName string) error {
	conn, adapter, err := getBluetoothDBus()
	if err != nil {
		return err
	}

	call := adapter.Call("org.bluez.Adapter1.StartDiscovery", 0)
	if call.Err != nil {
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

	// SMURF remove trusted!
	if err := conn.Export(&basicAgent{logger: n.logger, conn: conn, trusted: []string{"FC:41:16:BF:6D:98"}}, BluezAgentPath, BluezAgent); err != nil {
		return errw.Wrap(err, "exporting custom agent object")
	}

	obj := conn.Object(BluezDBusService, "/org/bluez")
	call = obj.Call("org.bluez.AgentManager1.RegisterAgent", 0, dbus.ObjectPath(BluezAgentPath), "DisplayYesNo")
	if err := call.Err; err != nil {
		return errw.Wrap(err, "registering custom agent")
	}

	call = obj.Call("org.bluez.AgentManager1.RequestDefaultAgent", 0, dbus.ObjectPath(BluezAgentPath))
	if err := call.Err; err != nil {
		return fmt.Errorf("failed to set default agent: %w", err)
	}

	n.logger.Debug("bluetooth pairing enabled")
	return nil
}

func (n *Networking) disablePairing() error {
	conn, adapter, err := getBluetoothDBus()
	if err != nil {
		return err
	}

	call := adapter.Call("org.bluez.Adapter1.StopDiscovery", 0)
	if call.Err != nil {
		return err
	}

	obj := conn.Object(BluezDBusService, "/org/bluez")
	call = obj.Call("org.bluez.AgentManager1.UnregisterAgent", 0, dbus.ObjectPath(BluezAgentPath))
	if err := call.Err; err != nil {
		n.logger.Warnf("failed to unregister a bluez agent: %v", err)
	}

	n.logger.Debug("setting bluetooth to NOT discoverable")
	err = adapter.SetProperty("org.bluez.Adapter1.Discoverable", dbus.MakeVariant(false))
	if err != nil {
		return errw.Wrap(err, "disabling bluetooth discovery")
	}
	n.logger.Debug("bluetooth pairing disabled")
	return nil
}
