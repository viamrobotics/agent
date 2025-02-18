package provisioning

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"errors"

	"go.viam.com/rdk/logging"
	"go.viam.com/utils"
)

// bluetoothWiFiProvisioner provides an interface for managing BLE (bluetooth-low-energy) peripheral advertisement on Linux.
type bluetoothWiFiProvisioner struct{}

// Start begins advertising a bluetooth service that acccepts WiFi and Viam cloud config credentials.
func (bwp *bluetoothWiFiProvisioner) Start(ctx context.Context) error {
	if err := bwp.startAdvertisingBLE(ctx); err != nil {
		return err
	}
	bwp.enableAutoAcceptPairRequest() // Async goroutine (hence no error check) which auto-accepts pair requests on this device.
	return nil
}

// Stop stops advertising a bluetooth service which (when enabled) accepts WiFi and Viam cloud config credentials.
func (bwp *bluetoothWiFiProvisioner) Stop() error {
	return bwp.stopAdvertisingBLE()
}

// Update updates the list of networks that are advertised via bluetooth as available.
func (bwp *bluetoothWiFiProvisioner) RefreshAvailableNetworks(ctx context.Context, awns []*NetworkInfo) error {
	return bwp.writeAvailableNetworks(ctx, awns)
}

// WaitForCredentials returns credentials, the minimum required information to provision a robot and/or its WiFi.
func (bwp *bluetoothWiFiProvisioner) WaitForCredentials(
	ctx context.Context, requiresCloudCredentials bool, requiresWiFiCredentials bool,
) (*userInput, error) {
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
	return &userInput{
		SSID: ssid, PSK: psk, PartID: robotPartKeyID, Secret: robotPartKey,
	}, errors.Join(ssidErr, pskErr, robotPartKeyIDErr, robotPartKeyErr)
}

/** Helper methods for low-level system calls and read/write requests to/from bluetooth characteristics **/

func (bwp *bluetoothWiFiProvisioner) startAdvertisingBLE(ctx context.Context) error {
	return errors.New("TODO APP-7651: Implement helper methods to start/stop advertising BLE connection")
}

func (bwp *bluetoothWiFiProvisioner) stopAdvertisingBLE() error {
	return errors.New("TODO APP-7651: Implement helper methods to start/stop advertising BLE connection")
}

func (bwp *bluetoothWiFiProvisioner) enableAutoAcceptPairRequest() {
	// TODO APP-7655: Implement method to auto-accept pairing requests to the BLE peripheral.
}

func (bwp *bluetoothWiFiProvisioner) writeAvailableNetworks(ctx context.Context, networks []*NetworkInfo) error {
	return errors.New("TODO APP-7652: Implement helper method to write update WiFi networks to BLE peripheral characteristic")
}

func (bwp *bluetoothWiFiProvisioner) readSsid() (string, error) {
	return "", errors.New("TODO APP-7653: Implement helper methods to read SSID, passkey, robot part key ID, and robot part key" +
		" values from BLE peripheral characteristics")
}

func (bwp *bluetoothWiFiProvisioner) readPsk() (string, error) {
	return "", errors.New("TODO APP-7653: Implement helper methods to read SSID, passkey, robot part key ID, and robot part key" +
		" values from BLE peripheral characteristics")
}

func (bwp *bluetoothWiFiProvisioner) readRobotPartKeyID() (string, error) {
	return "", errors.New("TODO APP-7653: Implement helper methods to read SSID, passkey, robot part key ID, and robot part key" +
		" values from BLE peripheral characteristics")
}

func (bwp *bluetoothWiFiProvisioner) readRobotPartKey() (string, error) {
	return "", errors.New("TODO APP-7653: Implement helper methods to read SSID, passkey, robot part key ID, and robot part key" +
		" values from BLE peripheral characteristics")
}

// NewBluetoothWiFiProvisioner returns a service which accepts credentials over bluetooth to provision a robot and its WiFi connection.
func NewBluetoothWiFiProvisioner(ctx context.Context, logger logging.Logger, name string) (*bluetoothWiFiProvisioner, error) {
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

/** Custom error type and miscellaneous utils that are helpful for managing low-level bluetooth on Linux **/

// emptyBluetoothCharacteristicError represents the error which is raised when we attempt to read from an empty BLE characteristic.
type emptyBluetoothCharacteristicError struct {
	missingValue string
}

func (e *emptyBluetoothCharacteristicError) Error() string {
	return fmt.Sprintf("no value has been written to BLE characteristic for %s", e.missingValue)
}

// retryCallbackOnExpectedError retries the provided callback to at one second intervals as long as an expected error is thrown.
func retryCallbackOnExpectedError(
	ctx context.Context, fn func() (string, error), expectedErr error, description string,
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
			if errors.As(err, &expectedErr) {
				continue
			}
			return "", fmt.Errorf("%w: %s", err, description)
		}
		return v, nil
	}
}
