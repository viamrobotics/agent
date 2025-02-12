// Package bluetooth contains an interface for using bluetooth to retrieve WiFi and robot part credentials for an unprovisioned Viam agent.
package bluetooth

import (
	"context"
	"sync"
	"time"

	"github.com/pkg/errors"
	ble "github.com/viamrobotics/agent/subsystems/provisioning/bluetooth/bluetooth_low_energy"
	"go.uber.org/multierr"
	"go.viam.com/rdk/logging"
	"go.viam.com/utils"
)

// BluetoothWiFiProvisioner provides an interface for managing the bluetooth (bluetooth-low-energy) service as it pertains to WiFi setup.
type BluetoothWiFiProvisioner interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	Update(ctx context.Context, awns *ble.AvailableWiFiNetworks) error
	WaitForCredentials(ctx context.Context) (*credentials, error)
}

// BluetoothManager provides an interface for managing a BLE (bluetooth-low-energy) peripheral advertisement on Linux.
type bluetoothWiFiProvisioner struct {
	bleService ble.BLEService
}

// Start begins advertising a bluetooth service that acccepts WiFi and Viam cloud config credentials.
func (bm *bluetoothWiFiProvisioner) Start(ctx context.Context) error {
	return bm.bleService.StartAdvertising(ctx)
}

// Stop stops advertising a bluetooth service which (when enabled) accepts WiFi and Viam cloud config credentials.
func (bm *bluetoothWiFiProvisioner) Stop(ctx context.Context) error {
	return bm.bleService.StopAdvertising()
}

// Update updates the list of networks that are advertised via bluetooth as available.
func (bm *bluetoothWiFiProvisioner) Update(ctx context.Context, awns *ble.AvailableWiFiNetworks) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	bm.bleService.UpdateAvailableWiFiNetworks(awns)
	return nil
}

// WaitForCredentials returns credentials which represent the information required to provision a robot part and its WiFi.
func (bm *bluetoothWiFiProvisioner) WaitForCredentials(ctx context.Context) (*credentials, error) {
	var ssid, psk, robotPartKeyID, robotPartKey string
	var ssidErr, pskErr, robotPartKeyIDErr, robotPartKeyErr error

	wg := &sync.WaitGroup{}
	wg.Add(4)
	utils.ManagedGo(
		func() {
			ssid, ssidErr = waitForBLEValue(ctx, bm.bleService.ReadSsid, "ssid")
		},
		wg.Done,
	)
	utils.ManagedGo(
		func() {
			psk, pskErr = waitForBLEValue(ctx, bm.bleService.ReadPsk, "psk")
		},
		wg.Done,
	)
	utils.ManagedGo(
		func() {
			robotPartKeyID, robotPartKeyIDErr = waitForBLEValue(ctx, bm.bleService.ReadRobotPartKeyID, "robot part key ID")
		},
		wg.Done,
	)
	utils.ManagedGo(
		func() {
			robotPartKey, robotPartKeyErr = waitForBLEValue(ctx, bm.bleService.ReadRobotPartKey, "robot part key")
		},
		wg.Done,
	)
	wg.Wait()

	return &credentials{
		ssid: ssid, psk: psk, robotPartKeyID: robotPartKeyID, robotPartKey: robotPartKey,
	}, multierr.Combine(ssidErr, pskErr, robotPartKeyIDErr, robotPartKeyErr)
}

// NewBluetoothWiFiProvisioner returns a service which accepts credentials over bluetooth to provision a robot and its WiFi connection.
func NewBluetoothWiFiProvisioner(ctx context.Context, logger logging.Logger, name string) (BluetoothWiFiProvisioner, error) {
	bleService, err := ble.NewLinuxBLEService(ctx, logger, name)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to set up bluetooth-low-energy peripheral (Linux)")
	}
	return &bluetoothWiFiProvisioner{bleService: bleService}, nil
}

// credentials represents the minimum required information needed to provision a Viam Agent.
type credentials struct {
	ssid           string
	psk            string
	robotPartKeyID string
	robotPartKey   string
}

// GetSSID returns the SSID from a set of credentials.
func (c *credentials) GetSSID() string {
	return c.ssid
}

// GetPSK returns the passkey from a set of credentials.
func (c *credentials) GetPsk() string {
	return c.psk
}

// GetRobotPartKeyID returns the robot part key ID from a set of credentials.
func (c *credentials) GetRobotPartKeyID() string {
	return c.robotPartKeyID
}

// GetRobotPartKey returns the robot part key from a set of credentials.
func (c *credentials) GetRobotPartKey() string {
	return c.robotPartKey
}

// waitForBLE is used to check for the existence of a new value in a BLE characteristic.
func waitForBLEValue(
	ctx context.Context, fn func() (string, error), description string,
) (string, error) {
	for {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
			time.Sleep(time.Second)
		}
		v, err := fn()
		if err != nil {
			var errBLECharNoValue *ble.EmptyBluetoothCharacteristicError
			if errors.As(err, &errBLECharNoValue) {
				continue
			}
			return "", errors.WithMessagef(err, "failed to read %s", description)
		}
		return v, nil
	}
}
