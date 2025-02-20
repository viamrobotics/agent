package networking

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"go.viam.com/rdk/logging"
	"go.viam.com/utils"
)

// bluetoothService provides methods to retrieve cloud config and/or WiFi credentials for a robot over bluetooth.
type bluetoothService struct{}

// Start begins advertising a bluetooth service that acccepts WiFi and Viam cloud config credentials.
func (bwp *bluetoothService) start(ctx context.Context) error { //nolint:unused
	// TODO APP-7651: Implement helper methods to start/stop advertising BLE connection
	bwp.enableAutoAcceptPairRequest() // Async goroutine (hence no error check) which auto-accepts pair requests on this device.
	return errors.New("TODO APP-7651: Implement helper methods to start/stop advertising BLE connection")
}

// Stop stops advertising a bluetooth service which (when enabled) accepts WiFi and Viam cloud config credentials.
func (bwp *bluetoothService) stop() error { //nolint:unused
	return errors.New("TODO APP-7651: Implement helper methods to start/stop advertising BLE connection")
}

// Update updates the list of networks that are advertised via bluetooth as available.
func (bwp *bluetoothService) refreshAvailableNetworks(ctx context.Context, awns []*NetworkInfo) error { //nolint:unused
	return errors.New("TODO APP-7652: Implement helper method to write update WiFi networks to BLE peripheral characteristic")
}

// WaitForCredentials returns credentials, the minimum required information to provision a robot and/or its WiFi.
func (bwp *bluetoothService) waitForCredentials( //nolint:unused
	ctx context.Context, requiresCloudCredentials, requiresWiFiCredentials bool,
) (*userInput, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if !requiresWiFiCredentials && !requiresCloudCredentials {
		return nil, errors.New("should be waiting for cloud credentials or WiFi credentials, or both")
	}
	var ssid, psk, robotPartKeyID, robotPartKey string
	var ctxErr, ssidErr, pskErr, robotPartKeyIDErr, robotPartKeyErr error

	wg := sync.WaitGroup{}
	wg.Add(1)

	utils.ManagedGo(func() {
		for {
			if ctxErr = ctx.Err(); ctxErr != nil {
				return
			}
			select {
			case <-ctx.Done():
				ctxErr = ctx.Err()
				return
			default:
				if requiresWiFiCredentials {
					if ssid == "" {
						var e *emptyBluetoothCharacteristicError
						ssid, ssidErr = bwp.readSsid()
						if ssidErr != nil && !errors.As(ssidErr, &e) {
							return
						}
					}
					if psk == "" {
						var e *emptyBluetoothCharacteristicError
						psk, pskErr = bwp.readPsk()
						if pskErr != nil && !errors.As(pskErr, &e) {
							return
						}
					}
				}
				if requiresCloudCredentials {
					if robotPartKeyID == "" {
						var e *emptyBluetoothCharacteristicError
						robotPartKeyID, robotPartKeyIDErr = bwp.readRobotPartKeyID()
						if robotPartKeyIDErr != nil && !errors.As(robotPartKeyIDErr, &e) {
							return
						}
					}
					if robotPartKey == "" {
						var e *emptyBluetoothCharacteristicError
						robotPartKey, robotPartKeyErr = bwp.readRobotPartKey()
						if robotPartKeyErr != nil && !errors.As(robotPartKeyErr, &e) {
							return
						}
					}
				}
				if requiresWiFiCredentials && requiresCloudCredentials && //nolint:gocritic
					ssid != "" && psk != "" && robotPartKeyID != "" && robotPartKey != "" {
					return
				} else if requiresWiFiCredentials && ssid != "" && psk != "" {
					return
				} else if requiresCloudCredentials && robotPartKeyID != "" && robotPartKey != "" {
					return
				}

				// Not ready to return (do not have the minimum required set of credentials), so sleep and try again.
				time.Sleep(time.Second)
			}
		}
	}, wg.Done)

	wg.Wait()

	return &userInput{
		SSID: ssid, PSK: psk, PartID: robotPartKeyID, Secret: robotPartKey,
	}, errors.Join(ctxErr, ssidErr, pskErr, robotPartKeyIDErr, robotPartKeyErr)
}

/** Helper methods for low-level system calls and read/write requests to/from bluetooth characteristics **/

func (bwp *bluetoothService) enableAutoAcceptPairRequest() { //nolint:unused
	// TODO APP-7655: Implement method to auto-accept pairing requests to the BLE peripheral.
}

func (bwp *bluetoothService) readSsid() (string, error) { //nolint:unused
	return "", errors.New("TODO APP-7653: Implement helper methods to read SSID, passkey, robot part key ID, and robot part key" +
		" values from BLE peripheral characteristics")
}

func (bwp *bluetoothService) readPsk() (string, error) { //nolint:unused
	return "", errors.New("TODO APP-7653: Implement helper methods to read SSID, passkey, robot part key ID, and robot part key" +
		" values from BLE peripheral characteristics")
}

func (bwp *bluetoothService) readRobotPartKeyID() (string, error) { //nolint:unused
	return "", errors.New("TODO APP-7653: Implement helper methods to read SSID, passkey, robot part key ID, and robot part key" +
		" values from BLE peripheral characteristics")
}

func (bwp *bluetoothService) readRobotPartKey() (string, error) { //nolint:unused
	return "", errors.New("TODO APP-7653: Implement helper methods to read SSID, passkey, robot part key ID, and robot part key" +
		" values from BLE peripheral characteristics")
}

// NewBluetoothService returns a service which accepts credentials over bluetooth to provision a robot and its WiFi connection.
func NewBluetoothService(ctx context.Context, logger logging.Logger, name string) (*bluetoothService, error) {
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
type emptyBluetoothCharacteristicError struct { //nolint:unused
	missingValue string
}

func (e *emptyBluetoothCharacteristicError) Error() string { //nolint:unused
	return fmt.Sprintf("no value has been written to BLE characteristic for %s", e.missingValue)
}
