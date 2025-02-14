// Package ble contains an interface for using bluetooth-low-energy to retrieve WiFi and robot part credentials for an unprovisioned Agent.
package ble

import (
	"context"
	"encoding/json"
	"runtime"
	"sync"
	"time"

	"github.com/pkg/errors"
	"go.uber.org/multierr"
	"go.viam.com/rdk/logging"
	"go.viam.com/utils"
)

// Credentials represent the minimum required information needed to provision a Viam Agent.
type Credentials struct {
	Ssid           string
	Psk            string
	RobotPartKeyID string
	RobotPartKey   string
}

// AvailableWiFiNetworks represent the networks that the device has detected (and which may be available for connection).
type AvailableWiFiNetworks struct {
	Networks []*struct {
		Ssid        string  `json:"ssid"`
		Strength    float64 `json:"strength"` // Inclusive range [0.0, 1.0], represents the % strength of a WiFi network.
		RequiresPsk bool    `json:"requires_psk"`
	} `json:"networks"`
}

func (awns *AvailableWiFiNetworks) ToBytes() ([]byte, error) {
	return json.Marshal(awns)
}

// BluetoothWiFiProvisioner provides an interface for managing the bluetooth (bluetooth-low-energy) service as it pertains to WiFi setup.
type BluetoothWiFiProvisioner interface {
	Start(ctx context.Context) error
	Stop() error
	RefreshAvailableNetworks(ctx context.Context, awns *AvailableWiFiNetworks) error
	WaitForCredentials(ctx context.Context, requiresCloudCredentials bool, requiresWiFiCredentials bool) (*Credentials, error)
}

// linuxBluetoothWiFiProvisioner provides an interface for managing BLE (bluetooth-low-energy) peripheral advertisement on Linux.
type bluetoothWiFiProvisioner[T bluetoothService] struct {
	svc T
}

// Start begins advertising a bluetooth service that acccepts WiFi and Viam cloud config credentials.
func (bwp *bluetoothWiFiProvisioner[T]) Start(ctx context.Context) error {
	return bwp.svc.startAdvertisingBLE(ctx)
}

// Stop stops advertising a bluetooth service which (when enabled) accepts WiFi and Viam cloud config credentials.
func (bwp *bluetoothWiFiProvisioner[T]) Stop() error {
	return bwp.svc.stopAdvertisingBLE()
}

// Update updates the list of networks that are advertised via bluetooth as available.
func (bwp *bluetoothWiFiProvisioner[T]) RefreshAvailableNetworks(ctx context.Context, awns *AvailableWiFiNetworks) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return bwp.svc.writeAvailableNetworks(awns)
}

// WaitForCredentials returns credentials which represent the information required to provision a robot part and its WiFi.
func (bwp *bluetoothWiFiProvisioner[T]) WaitForCredentials(ctx context.Context, requiresCloudCredentials bool, requiresWiFiCredentials bool) (*Credentials, error) {
	if !requiresWiFiCredentials && !requiresCloudCredentials {
		return nil, errors.New("should be waiting for either cloud credentials or WiFi credentials")
	}
	var ssid, psk, robotPartKeyID, robotPartKey string
	var ssidErr, pskErr, robotPartKeyIDErr, robotPartKeyErr error
	wg := &sync.WaitGroup{}
	if requiresWiFiCredentials {
		wg.Add(2)
		utils.ManagedGo(
			func() {
				ssid, ssidErr = waitForBLEValue(ctx, bwp.svc.readSsid, "ssid")
			},
			wg.Done,
		)
		utils.ManagedGo(
			func() {
				psk, pskErr = waitForBLEValue(ctx, bwp.svc.readPsk, "psk")
			},
			wg.Done,
		)
	}
	if requiresCloudCredentials {
		wg.Add(2)
		utils.ManagedGo(
			func() {
				robotPartKeyID, robotPartKeyIDErr = waitForBLEValue(ctx, bwp.svc.readRobotPartKeyID, "robot part key ID")
			},
			wg.Done,
		)
		utils.ManagedGo(
			func() {
				robotPartKey, robotPartKeyErr = waitForBLEValue(ctx, bwp.svc.readRobotPartKey, "robot part key")
			},
			wg.Done,
		)
	}
	wg.Wait()
	return &Credentials{
		Ssid: ssid, Psk: psk, RobotPartKeyID: robotPartKeyID, RobotPartKey: robotPartKey,
	}, multierr.Combine(ssidErr, pskErr, robotPartKeyIDErr, robotPartKeyErr)
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
			var errBLECharNoValue *emptyBluetoothCharacteristicError
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
	var err error
	var svc bluetoothService
	switch os := runtime.GOOS; os {
	case "linux":
		svc, err = newLinuxBLEService(ctx, logger, name)
		if err != nil {
			return nil, errors.WithMessage(err, "failed to set up bluetooth-low-energy peripheral")
		}
	case "windows":
		fallthrough
	case "darwin":
		fallthrough
	default:
		return nil, errors.Errorf("failed to set up bluetooth-low-energy peripheral, %s is not yet supported")
	}
	return &bluetoothWiFiProvisioner[bluetoothService]{svc: svc}, nil
}
