package networking

import (
	"context"
	"fmt"
	"sync"
	"time"

	dbus "github.com/godbus/dbus/v5"
	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
)

var errPairingRejected = &dbus.Error{Name: "org.bluez.Error.Rejected"}

// this will be the bluetooth "agent" used for pairing requests.
type basicAgent struct {
	mu      sync.Mutex
	conn    *dbus.Conn
	logger  logging.Logger
	trusted map[string]bool

	workers sync.WaitGroup
	cancel  context.CancelFunc

	networking *Networking
}

func (b *basicAgent) TrustDevice(bdaddr string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.trusted[bdaddr] = true
}

func (b *basicAgent) Cancel() *dbus.Error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cancel != nil {
		b.cancel()
	}
	return nil
}

// passkey style requests (six digit number).
func (b *basicAgent) RequestConfirmation(devicePath dbus.ObjectPath, passkey uint32) *dbus.Error {
	return b.RequestAuthorization(devicePath)
}

// generic requests, we compare the HW address to accept/deny.
func (b *basicAgent) RequestAuthorization(devicePath dbus.ObjectPath) *dbus.Error {
	conn, _, err := getBluetoothDBus()
	if err != nil {
		b.logger.Error(err)
		return errPairingRejected
	}

	remoteDev := conn.Object(BluezDBusService, devicePath)

	ret, err := remoteDev.GetProperty("org.bluez.Device1.Address")
	if err != nil {
		b.logger.Error(err)
		return errPairingRejected
	}
	bdaddr := ret.Value().(string)

	ret, err = remoteDev.GetProperty("org.bluez.Device1.Alias")
	if err != nil {
		b.logger.Error(err)
	}
	alias := ret.Value().(string)

	b.mu.Lock()
	defer b.mu.Unlock()

	b.logger.Infof("Bluetooth pairing request from: %s", bdaddr)

	trusted, ok := b.trusted[bdaddr]
	if !(ok && trusted) {
		b.logger.Errorf("Bluetooth device pairing rejected for %s (%s), device address must be added via provisioning first.", bdaddr, alias)
		return errPairingRejected
	}

	if err := remoteDev.SetProperty("org.bluez.Device1.Trusted", true); err != nil {
		b.logger.Error(errw.Wrapf(err, "trusting bluetooth device %s (%s)", bdaddr, alias))
	} else {
		b.logger.Infof("Bluetooth device paired/trusted: %s (%s)", bdaddr, alias)
	}

	b.workers.Add(1)
	ctx, cancel := context.WithTimeout(context.Background(), BluetoothPairingTimeout)
	b.cancel = cancel
	go func() {
		defer cancel()
		defer b.workers.Done()
		var allGood bool
		defer func() {
			if !allGood {
				b.logger.Warnf("failed to fully set up bluetooth tethering for %s (%s)", bdaddr, alias)
			}
		}()

		for {
			// break if our context times out or is cancelled
			if ctx.Err() != nil {
				return
			}

			// want to be paired and services resolved
			ret, err := remoteDev.GetProperty("org.bluez.Device1.Paired")
			if err != nil {
				b.logger.Warn(errw.Wrapf(err, "cannot get paired status for bluetooth device: %s (%s)", bdaddr, alias))
			}
			paired := ret.Value().(bool)

			ret, err = remoteDev.GetProperty("org.bluez.Device1.ServicesResolved")
			if err != nil {
				b.logger.Warn(errw.Wrapf(err, "cannot get service resolution status for bluetooth device: %s (%s)", bdaddr, alias))
			}
			resolved := ret.Value().(bool)

			if paired && resolved {
				break
			}

			if !b.networking.mainLoopHealth.Sleep(ctx, time.Second) {
				b.logger.Warn("timed out waiting for bluetooth pairing and service discovery to complete")
				return
			}
		}
		call := remoteDev.CallWithContext(ctx, "org.bluez.Device1.ConnectProfile", 0, "00001115-0000-1000-8000-00805f9b34fb")
		if err := call.Err; err != nil {
			b.logger.Error(errw.Wrapf(err, "connecting bluetooth device: %s", bdaddr))
		}

		tetherCfg := utils.NetworkDefinition{
			Type:             NetworkTypeBluetooth,
			BluetoothAddress: bdaddr,
		}
		_, err := b.networking.AddOrUpdateConnection(tetherCfg)
		if err != nil {
			b.logger.Error(errw.Wrapf(err, "adding tethering config for: %s", bdaddr))
		} else {
			allGood = true
			b.logger.Infof("Added bluetooth device for tethering: %s", bdaddr)
		}

		if !b.networking.tryBluetoothTether(ctx) {
			b.logger.Info("Bluetooth tethering failed to immediately activate and will be retried. It may take one to two minutes in some cases.")
		}
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
		return call.Err
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
	n.btAgent = &basicAgent{
		logger:     n.logger,
		conn:       conn,
		networking: n,
		trusted:    map[string]bool{"FC:41:16:BF:6D:98": true},
	}

	if err := conn.Export(n.btAgent, BluezAgentPath, BluezAgent); err != nil {
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
		return call.Err
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

	//nolint:errcheck
	n.btAgent.Cancel()
	n.btAgent.workers.Wait()

	n.logger.Debug("bluetooth pairing disabled")
	return nil
}
