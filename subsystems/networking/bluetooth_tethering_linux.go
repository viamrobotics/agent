package networking

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	dbus "github.com/godbus/dbus/v5"
	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
)

var errPairingRejected = &dbus.Error{Name: "org.bluez.Error.Rejected"}

// this will be the bluetooth "agent" used for pairing requests.
type pairingAgent struct {
	mu       sync.Mutex
	conn     *dbus.Conn
	logger   logging.Logger
	trusted  map[string]bool
	trustAll bool
	pairable bool

	workers sync.WaitGroup
	cancel  context.CancelFunc

	networking *Networking
}

func (b *pairingAgent) TrustAll(trust bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pairable = trust
}

func (b *pairingAgent) TrustDevice(bdaddr string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	trusted, ok := b.trusted[bdaddr]
	if !ok || !trusted {
		b.logger.Infof("Adding %s to the list of trusted bluetooth devices for pairing/tethering", bdaddr)
		b.trusted[bdaddr] = true
	}
}

func (b *pairingAgent) Cancel() *dbus.Error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.cancel != nil {
		b.cancel()
	}
	return nil
}

// passkey style requests (six digit number).
func (b *pairingAgent) RequestConfirmation(devicePath dbus.ObjectPath, passkey uint32) *dbus.Error {
	return b.RequestAuthorization(devicePath)
}

// generic requests, we compare the HW address to accept/deny.
func (b *pairingAgent) RequestAuthorization(devicePath dbus.ObjectPath) *dbus.Error {
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
	bdaddr := strings.ToUpper(ret.Value().(string))

	ret, err = remoteDev.GetProperty("org.bluez.Device1.Alias")
	if err != nil {
		b.logger.Error(err)
	}
	alias := ret.Value().(string)

	b.logger.Infof("Bluetooth pairing request from: %s (%s)", bdaddr, alias)

	b.mu.Lock()
	defer b.mu.Unlock()
	trusted, ok := b.trusted[bdaddr]
	if !(ok && trusted) && !b.trustAll && !b.pairable {
		b.logger.Errorf("Bluetooth device pairing rejected for %s (%s), device address must be added via provisioning first.", bdaddr, alias)
		return errPairingRejected
	}

	tetherCfg := utils.NetworkDefinition{
		Type:      NetworkTypeBluetooth,
		Interface: bdaddr,
	}
	_, err = b.networking.AddOrUpdateConnection(tetherCfg)
	if err != nil {
		b.logger.Error(errw.Wrapf(err, "adding/updating tethering config for %s (%s)", bdaddr, alias))
	} else {
		b.logger.Infof("Added network manager profile for tethering with %s (%s)", bdaddr, alias)
	}

	if err := remoteDev.SetProperty("org.bluez.Device1.Trusted", true); err != nil {
		b.logger.Error(errw.Wrapf(err, "setting trust property for bluetooth device %s (%s)", bdaddr, alias))
	}

	b.workers.Add(1)
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	b.cancel = cancel
	go func() {
		defer cancel()
		defer b.workers.Done()

		var paired bool
		defer func() {
			switch {
			case b.networking.connState.getOnline():
				b.logger.Infof("Bluetooth tethering fully online.")
			case paired:
				b.logger.Warnf("Failed to fully connect to the internet via tethering. Will keep trying. " +
					"Please retry pairing if not online in five minutes.")
			default:
				b.logger.Warnf("Failed to complete bluetooth pairing. Please retry the pairing process.")
			}
		}()

		for !paired {
			// break if our context times out or is cancelled
			if !b.networking.mainLoopHealth.Sleep(ctx, time.Second) {
				b.logger.Warn("timed out waiting for bluetooth pairing to complete")
				return
			}

			ret, err := remoteDev.GetProperty("org.bluez.Device1.Paired")
			if err != nil {
				b.logger.Warn(errw.Wrapf(err, "cannot get paired status for bluetooth device: %s (%s)", bdaddr, alias))
			} else if ret.Value() != nil {
				paired = ret.Value().(bool)
			}
		}

		// We have to connect something to make service discovery happen (this is a workaround probably specific to Bluez/Linux)
		// We use a fake service UUID as we don't care about the actual connection, but the phone needs to see the request to
		// not consider pairing as "failed"
		call := remoteDev.CallWithContext(ctx, "org.bluez.Device1.ConnectProfile", 0, "deadbeef-cafe-0000-0000-cafedeadbeef")
		if call.Err.Error() != "br-connection-profile-unavailable" {
			b.logger.Warnf("temporarily connecting bluetooth device %s (%s) resulted in unexpected error: %s",
				bdaddr, alias, call.Err.Error())
		}

		// every bluetooth device is new, so have to scan after a new pairing
		b.networking.dataMu.Lock()
		if err := b.networking.initDevices(); err != nil {
			b.logger.Warn(err)
		}
		b.networking.dataMu.Unlock()
		b.logger.Infof("Bluetooth tethering (setup phase) complete, may take up to 60 seconds to get online.")

		for b.networking.mainLoopHealth.Sleep(ctx, time.Second) {
			if err := b.networking.checkOnline(ctx, true); err != nil {
				b.logger.Warn(err)
			}
			if b.networking.connState.getOnline() {
				break
			}
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

	n.btAgent.mu.Lock()
	n.btAgent.conn = conn
	// remove temporary pairing approval if leftover from previous invocation
	n.btAgent.pairable = false
	n.btAgent.mu.Unlock()

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
