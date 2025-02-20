package networking

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

// bluetoothService provides an interface for retrieving cloud config and WiFi credentials for a robot over bluetooth.
type bluetoothService interface {
	start(ctx context.Context) error
	stop() error
	refreshAvailableNetworks(ctx context.Context, availableNetworks []*NetworkInfo) error
	waitForCredentials(ctx context.Context, requiresCloudCredentials, requiresWiFiCredentials bool) (*userInput, error)
}

// bluetoothServiceLinux provides methods to retrieve cloud config and WiFi credentials for a robot over bluetooth.
type bluetoothServiceLinux struct{}

// Start begins advertising a bluetooth service that acccepts WiFi and Viam cloud config credentials.
func (bwp *bluetoothServiceLinux) start(ctx context.Context) error {
	// TODO APP-7651: Implement helper methods to start/stop advertising BLE connection
	bwp.enableAutoAcceptPairRequest() // Async goroutine (hence no error check) which auto-accepts pair requests on this device.
	return errors.New("TODO APP-7651: Implement helper methods to start/stop advertising BLE connection")
}

// Stop stops advertising a bluetooth service which (when enabled) accepts WiFi and Viam cloud config credentials.
func (bwp *bluetoothServiceLinux) stop() error {
	return errors.New("TODO APP-7651: Implement helper methods to start/stop advertising BLE connection")
}

// Update updates the list of networks that are advertised via bluetooth as available.
func (bwp *bluetoothServiceLinux) refreshAvailableNetworks(ctx context.Context, awns []*NetworkInfo) error {
	return errors.New("TODO APP-7652: Implement helper method to write update WiFi networks to BLE peripheral characteristic")
}

// WaitForCredentials returns credentials, the minimum required information to provision a robot and/or its WiFi.
func (bwp *bluetoothServiceLinux) waitForCredentials(
	ctx context.Context, requiresCloudCredentials bool, requiresWiFiCredentials bool,
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
						ssid, ssidErr = bwp.readSsid()
						if ssidErr != nil && !errors.As(ssidErr, emptyBluetoothCharacteristicError{}) {
							return
						}
					}
					if psk == "" {
						psk, pskErr = bwp.readPsk()
						if pskErr != nil && !errors.As(pskErr, emptyBluetoothCharacteristicError{}) {
							return
						}
					}
				}
				if requiresCloudCredentials {
					if robotPartKeyID == "" {
						robotPartKeyID, robotPartKeyIDErr = bwp.readRobotPartKeyID()
						if robotPartKeyIDErr != nil && !errors.As(robotPartKeyIDErr, emptyBluetoothCharacteristicError{}) {
							return
						}
					}
					if robotPartKey == "" {
						robotPartKey, robotPartKeyErr = bwp.readRobotPartKey()
						if robotPartKeyErr != nil && !errors.As(robotPartKeyErr, emptyBluetoothCharacteristicError{}) {
							return
						}
					}
				}
				if requiresWiFiCredentials && requiresCloudCredentials &&
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

func (bwp *bluetoothServiceLinux) enableAutoAcceptPairRequest() {
	// TODO APP-7655: Implement method to auto-accept pairing requests to the BLE peripheral.
}

func (bwp *bluetoothServiceLinux) readSsid() (string, error) {
	return "", errors.New("TODO APP-7653: Implement helper methods to read SSID, passkey, robot part key ID, and robot part key" +
		" values from BLE peripheral characteristics")
}

func (bwp *bluetoothServiceLinux) readPsk() (string, error) {
	return "", errors.New("TODO APP-7653: Implement helper methods to read SSID, passkey, robot part key ID, and robot part key" +
		" values from BLE peripheral characteristics")
}

func (bwp *bluetoothServiceLinux) readRobotPartKeyID() (string, error) {
	return "", errors.New("TODO APP-7653: Implement helper methods to read SSID, passkey, robot part key ID, and robot part key" +
		" values from BLE peripheral characteristics")
}

func (bwp *bluetoothServiceLinux) readRobotPartKey() (string, error) {
	return "", errors.New("TODO APP-7653: Implement helper methods to read SSID, passkey, robot part key ID, and robot part key" +
		" values from BLE peripheral characteristics")
}

// NewBluetoothWiFiProvisioningServiceLinux returns a service which accepts credentials over bluetooth to provision a robot and its WiFi connection.
func NewBluetoothWiFiProvisioningService(ctx context.Context, logger logging.Logger, name string) (*bluetoothServiceLinux, error) {
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
