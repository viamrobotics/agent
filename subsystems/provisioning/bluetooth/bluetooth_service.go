// Package ble contains an interface for interacting with the bluetooth stack on a Linux device, specifically with respect to provisioning.
package ble

import (
	"context"
	"fmt"
)

type bluetoothService interface {
	startAdvertisingBLE(ctx context.Context) error
	stopAdvertisingBLE() error
	enableAutoAcceptPairRequest()

	// Available WiFi networks need to be written to a bluetooth service. Clients read from this inputted data.
	writeAvailableNetworks(networks *AvailableWiFiNetworks) error

	// Credentials that ae written by a client need to be extracted from a bluetooth service.
	readSsid() (string, error)
	readPsk() (string, error)
	readRobotPartKeyID() (string, error)
	readRobotPartKey() (string, error)
}

// emptyBluetoothCharacteristicError represents the error which is raised when we attempt to read from an empty BLE characteristic.
type emptyBluetoothCharacteristicError struct {
	missingValue string
}

func (e *emptyBluetoothCharacteristicError) Error() string {
	return fmt.Sprintf("no value has been written to BLE characteristic for %s", e.missingValue)
}

func newEmptyBluetoothCharacteristicError(missingValue string) error {
	return &emptyBluetoothCharacteristicError{
		missingValue: missingValue,
	}
}
