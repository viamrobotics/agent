// Package ble contains an interface for using bluetooth-low-energy to retrieve WiFi and robot part credentials for an unprovisioned Agent.
package ble

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"sync"

	"errors"

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

// BluetoothWiFiProvisioner provides an interface for managing BLE (bluetooth-low-energy) peripheral advertisement on Linux.
type BluetoothWiFiProvisioner struct{}

// Start begins advertising a bluetooth service that acccepts WiFi and Viam cloud config credentials.
func (bwp *BluetoothWiFiProvisioner) Start(ctx context.Context) error {
	if err := bwp.startAdvertisingBLE(ctx); err != nil {
		return err
	}
	bwp.enableAutoAcceptPairRequest() // Async goroutine (hence no error check) which auto-accepts pair requests on this device.
	return nil
}

// Stop stops advertising a bluetooth service which (when enabled) accepts WiFi and Viam cloud config credentials.
func (bwp *BluetoothWiFiProvisioner) Stop() error {
	return bwp.stopAdvertisingBLE()
}

// Update updates the list of networks that are advertised via bluetooth as available.
func (bwp *BluetoothWiFiProvisioner) RefreshAvailableNetworks(ctx context.Context, awns *AvailableWiFiNetworks) error {
	return bwp.writeAvailableNetworks(ctx, awns)
}

// WaitForCredentials returns credentials, the minimum required information to provision a robot and/or its WiFi.
func (bwp *BluetoothWiFiProvisioner) WaitForCredentials(
	ctx context.Context, requiresCloudCredentials bool, requiresWiFiCredentials bool,
) (*Credentials, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if !requiresWiFiCredentials && !requiresCloudCredentials {
		return nil, errors.New("should be waiting for cloud credentials or WiFi credentials, or both")
	}
	var ssid, psk, robotPartKeyID, robotPartKey string
	var ssidErr, pskErr, robotPartKeyIDErr, robotPartKeyErr error
	wg := sync.WaitGroup{}
	if requiresWiFiCredentials {
		wg.Add(2)
		utils.ManagedGo(
			func() {
				if ssid, ssidErr = retryCallbackOnExpectedError(
					ctx, bwp.readSsid, &emptyBluetoothCharacteristicError{}, "failed to read ssid",
				); ssidErr != nil {
					cancel()
				}
			},
			wg.Done,
		)
		utils.ManagedGo(
			func() {
				if psk, pskErr = retryCallbackOnExpectedError(
					ctx, bwp.readPsk, &emptyBluetoothCharacteristicError{}, "failed to read psk",
				); pskErr != nil {
					cancel()
				}

			},
			wg.Done,
		)
	}
	if requiresCloudCredentials {
		wg.Add(2)
		utils.ManagedGo(
			func() {
				if robotPartKeyID, robotPartKeyIDErr = retryCallbackOnExpectedError(
					ctx, bwp.readRobotPartKeyID, &emptyBluetoothCharacteristicError{}, "failed to read robot part key ID",
				); robotPartKeyIDErr != nil {
					cancel()
				}
			},
			wg.Done,
		)
		utils.ManagedGo(
			func() {
				if robotPartKey, robotPartKeyErr = retryCallbackOnExpectedError(
					ctx, bwp.readRobotPartKey, &emptyBluetoothCharacteristicError{}, "failed to read robot part key",
				); robotPartKeyErr != nil {
					cancel()
				}
			},
			wg.Done,
		)
	}
	wg.Wait()
	return &Credentials{
		Ssid: ssid, Psk: psk, RobotPartKeyID: robotPartKeyID, RobotPartKey: robotPartKey,
	}, errors.Join(ssidErr, pskErr, robotPartKeyIDErr, robotPartKeyErr)
}

/** Unexported helper methods for low-level system calls and read/write requests to/from bluetooth characteristics **/

func (bwp *BluetoothWiFiProvisioner) startAdvertisingBLE(ctx context.Context) error {
	return errors.New("TODO APP-7651: Implement helper methods to start/stop advertising BLE connection")
}

func (bwp *BluetoothWiFiProvisioner) stopAdvertisingBLE() error {
	return errors.New("TODO APP-7651: Implement helper methods to start/stop advertising BLE connection")
}

func (bwp *BluetoothWiFiProvisioner) enableAutoAcceptPairRequest() {
	// TODO APP-7655: Implement method to auto-accept pairing requests to the BLE peripheral.
}

func (bwp *BluetoothWiFiProvisioner) writeAvailableNetworks(ctx context.Context, networks *AvailableWiFiNetworks) error {
	return errors.New("TODO APP-7652: Implement helper method to write update WiFi networks to BLE peripheral characteristic")
}

func (bwp *BluetoothWiFiProvisioner) readSsid() (string, error) {
	return "", errors.New("TODO APP-7653: Implement helper methods to read SSID, passkey, robot part key ID, and robot part key" +
		" values from BLE peripheral characteristics")
}

func (bwp *BluetoothWiFiProvisioner) readPsk() (string, error) {
	return "", errors.New("TODO APP-7653: Implement helper methods to read SSID, passkey, robot part key ID, and robot part key" +
		" values from BLE peripheral characteristics")
}

func (bwp *BluetoothWiFiProvisioner) readRobotPartKeyID() (string, error) {
	return "", errors.New("TODO APP-7653: Implement helper methods to read SSID, passkey, robot part key ID, and robot part key" +
		" values from BLE peripheral characteristics")
}

func (bwp *BluetoothWiFiProvisioner) readRobotPartKey() (string, error) {
	return "", errors.New("TODO APP-7653: Implement helper methods to read SSID, passkey, robot part key ID, and robot part key" +
		" values from BLE peripheral characteristics")
}

// NewBluetoothWiFiProvisioner returns a service which accepts credentials over bluetooth to provision a robot and its WiFi connection.
func NewBluetoothWiFiProvisioner(ctx context.Context, logger logging.Logger, name string) (*BluetoothWiFiProvisioner, error) {
	switch os := runtime.GOOS; os {
	case "linux":
		// TODO APP-7654: Implement initializer function for creating a BLE peripheral with the required set of characteristics for BLE
		// to WiFi provisioning.
		fallthrough
	case "windows":
		fallthrough
	case "darwin":
		fallthrough
	default:
		return nil, fmt.Errorf("failed to set up bluetooth-low-energy peripheral, %s is not yet supported", os)
	}
}
