// Package bluetooth contains an interface for using bluetooth to retrieve WiFi and robot part credentials for an unprovisioned Viam agent.
package bluetooth

import (
	"context"
	"encoding/json"
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
	RefreshAvailableWiFi(ctx context.Context, awns *AvailableWiFiNetworks) error
	WaitForCloudCredentials(ctx context.Context) (*CloudCredentials, error)
	WaitForWiFiCredentials(ctx context.Context) (*WiFiCredentials, error)
}

// CloudCredentials represent the information needed by the Agent to assign the device a corresponding cloud robot.
type CloudCredentials struct {
	RobotPartKeyID string
	RobotPartKey   string
}

// WiFiCredentials represent the information needed by the Agent to provision WiFi in the system network manager.
type WiFiCredentials struct {
	Ssid string
	Psk  string
}

// AvailableWiFiNetworks represent the information needed by the client to display WiFi networks that are accessible by the device.
type AvailableWiFiNetworks struct {
	Networks []*struct {
		Ssid        string  `json:"ssid"`
		Strength    float64 `json:"strength"` // Inclusive range [0.0, 1.0], represents the percentage strength of a WiFi network.
		RequiresPsk bool    `json:"requires_psk"`
	} `json:"networks"`
}

// ToBytes represents a list of available WiFi networks as bytes, which is essential for transmitting the information over bluetooth.
func (awns *AvailableWiFiNetworks) ToBytes() ([]byte, error) {
	return json.Marshal(awns)
}

// bluetoothWiFiProvisioner provides an interface for managing a BLE (bluetooth-low-energy) peripheral advertisement on Linux.
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

// RefreshAvailableWiFi updates the list of networks that are advertised via bluetooth as available for connection.
func (bm *bluetoothWiFiProvisioner) RefreshAvailableWiFi(ctx context.Context, awns *ble.AvailableWiFiNetworks) error {
	return nil
}

// WaitForCloudCredentials returns cloud credentials which represent the information required to provision a device as a cloud robot.
func (bm *bluetoothWiFiProvisioner) WaitForCloudCredentials(ctx context.Context) (*CloudCredentials, error) {
	var robotPartKeyID, robotPartKey string
	var robotPartKeyIDErr, robotPartKeyErr error

	wg := &sync.WaitGroup{}
	wg.Add(2)
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

	return &CloudCredentials{RobotPartKeyID: robotPartKeyID, RobotPartKey: robotPartKey}, multierr.Combine(robotPartKeyIDErr, robotPartKeyErr)
}

// WaitForWiFiCredentials returns WiFi credentials which represent the information required to provision WiFi ona device.
func (bm *bluetoothWiFiProvisioner) WaitForWiFiCredentials(ctx context.Context) (*WiFiCredentials, error) {
	var ssid, psk string
	var ssidErr, pskErr error

	wg := &sync.WaitGroup{}
	wg.Add(2)
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
	wg.Wait()

	return &WiFiCredentials{Ssid: ssid, Psk: psk}, multierr.Combine(ssidErr, pskErr)
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

// NewBluetoothWiFiProvisioner returns a service which accepts credentials over bluetooth to provision a robot and its WiFi connection.
func NewBluetoothWiFiProvisioner(ctx context.Context, logger logging.Logger, name string) (BluetoothWiFiProvisioner, error) {
	bleService, err := ble.NewLinuxBLEService(ctx, logger, name)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to set up bluetooth-low-energy peripheral (Linux)")
	}
	return &bluetoothWiFiProvisioner{bleService: bleService}, nil
}
