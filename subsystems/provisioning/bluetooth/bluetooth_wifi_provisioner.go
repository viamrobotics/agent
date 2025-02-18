// Package ble contains an interface for using bluetooth-low-energy to retrieve WiFi and robot part credentials for an unprovisioned Agent.
package ble

import (
	"context"
	"encoding/json"
	"runtime"
	"sync"

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

// bluetoothWiFiProvisioner provides an interface for managing BLE (bluetooth-low-energy) peripheral advertisement on Linux.
type BluetoothWiFiProvisioner struct{}

// Start begins advertising a bluetooth service that acccepts WiFi and Viam cloud config credentials.
func (bwp *BluetoothWiFiProvisioner) Start(ctx context.Context) error {
	if err := bwp.startAdvertisingBLE(ctx); err != nil {
		return err
	}
	bwp.enableAutoAcceptPairRequest() // Enables auto-accept of pair request on this device.
	return nil
}

// Stop stops advertising a bluetooth service which (when enabled) accepts WiFi and Viam cloud config credentials.
func (bwp *BluetoothWiFiProvisioner) Stop() error {
	return bwp.stopAdvertisingBLE()
}

// Update updates the list of networks that are advertised via bluetooth as available.
func (bwp *BluetoothWiFiProvisioner) RefreshAvailableNetworks(ctx context.Context, awns *AvailableWiFiNetworks) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return bwp.writeAvailableNetworks(awns)
}

// WaitForCredentials returns credentials, the minimum required information to provision a robot and/or its WiFi.
func (bwp *BluetoothWiFiProvisioner) WaitForCredentials(ctx context.Context, requiresCloudCredentials bool, requiresWiFiCredentials bool) (*Credentials, error) {
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
				ssid, ssidErr = waitForBLEValue(ctx, bwp.readSsid, "ssid")
			},
			wg.Done,
		)
		utils.ManagedGo(
			func() {
				psk, pskErr = waitForBLEValue(ctx, bwp.readPsk, "psk")
			},
			wg.Done,
		)
	}
	if requiresCloudCredentials {
		wg.Add(2)
		utils.ManagedGo(
			func() {
				robotPartKeyID, robotPartKeyIDErr = waitForBLEValue(ctx, bwp.readRobotPartKeyID, "robot part key ID")
			},
			wg.Done,
		)
		utils.ManagedGo(
			func() {
				robotPartKey, robotPartKeyErr = waitForBLEValue(ctx, bwp.readRobotPartKey, "robot part key")
			},
			wg.Done,
		)
	}
	wg.Wait()
	return &Credentials{
		Ssid: ssid, Psk: psk, RobotPartKeyID: robotPartKeyID, RobotPartKey: robotPartKey,
	}, multierr.Combine(ssidErr, pskErr, robotPartKeyIDErr, robotPartKeyErr)
}

/** Unexported helper methods for low-level system calls and read/write requests to/from bluetooth characteristics **/

func (bwp *BluetoothWiFiProvisioner) startAdvertisingBLE(ctx context.Context) error {
	return errors.New("TODO APP-7644: Add Linux-specific bluetooth calls for automatic pairing and read/write to BLE characteristics")
}

func (bwp *BluetoothWiFiProvisioner) stopAdvertisingBLE() error {
	return errors.New("TODO APP-7644: Add Linux-specific bluetooth calls for automatic pairing and read/write to BLE characteristics")
}

func (bwp *BluetoothWiFiProvisioner) enableAutoAcceptPairRequest() error {
	return errors.New("TODO APP-7644: Add Linux-specific bluetooth calls for automatic pairing and read/write to BLE characteristics")
}

func (bwp *BluetoothWiFiProvisioner) writeAvailableNetworks(networks *AvailableWiFiNetworks) error {
	return errors.New("TODO APP-7644: Add Linux-specific bluetooth calls for automatic pairing and read/write to BLE characteristics")
}

func (bwp *BluetoothWiFiProvisioner) readSsid() (string, error) {
	return "", errors.New("TODO APP-7644: Add Linux-specific bluetooth calls for automatic pairing and read/write to BLE characteristics")
}

func (bwp *BluetoothWiFiProvisioner) readPsk() (string, error) {
	return "", errors.New("TODO APP-7644: Add Linux-specific bluetooth calls for automatic pairing and read/write to BLE characteristics")
}

func (bwp *BluetoothWiFiProvisioner) readRobotPartKeyID() (string, error) {
	return "", errors.New("TODO APP-7644: Add Linux-specific bluetooth calls for automatic pairing and read/write to BLE characteristics")
}

func (bwp *BluetoothWiFiProvisioner) readRobotPartKey() (string, error) {
	return "", errors.New("TODO APP-7644: Add Linux-specific bluetooth calls for automatic pairing and read/write to BLE characteristics")
}

// NewBluetoothWiFiProvisioner returns a service which accepts credentials over bluetooth to provision a robot and its WiFi connection.
func NewBluetoothWiFiProvisioner(ctx context.Context, logger logging.Logger, name string) (*BluetoothWiFiProvisioner, error) {
	switch os := runtime.GOOS; os {
	case "linux":
		fallthrough
	case "windows":
		fallthrough
	case "darwin":
		fallthrough
	default:
		return nil, errors.Errorf("failed to set up bluetooth-low-energy peripheral, %s is not yet supported", os)
	}
}
