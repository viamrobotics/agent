// Package ble contains an interface for interacting with the bluetooth stack on a Linux device, specifically with respect to provisioning.
package ble

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	"go.viam.com/rdk/logging"
)

// BluetoothService represents an interface for managing a bluetooth-low-energy peripheral for reading WiFi and robot part credentials.
// It is the lowest-level interface, and its purpose is to abstract away operating-system and firmware specific differences on machines.
type BluetoothService interface {
	StartAdvertising(ctx context.Context) error
	StopAdvertising() error
	UpdateAvailableWiFiNetworks(awns *AvailableWiFiNetworks) error
	ReadSsid() (string, error)
	ReadPsk() (string, error)
	ReadRobotPartKeyID() (string, error)
	ReadRobotPartKey() (string, error)
}

type AvailableWiFiNetworks struct {
	Networks []*struct {
		Ssid        string  `json:"ssid"`
		Strength    float64 `json:"strength"` // In the inclusive range [0.0, 1.0], it represents the % strength of a WiFi network.
		RequiresPsk bool    `json:"requires_psk"`
	} `json:"networks"`
}

type linux struct{}

func NewLinuxBluetooth(ctx context.Context, logger logging.Logger, name string) (*linux, error) {
	return nil, errors.New("TODO [APP-7644]")
}

// StartAdvertising begins advertising a BLE service.
func (s *linux) StartAdvertising(ctx context.Context) error {
	return errors.New("TODO [APP-7644]")
}

// StopAdvertising stops advertising a BLE service.
func (s *linux) StopAdvertising() error {
	return errors.New("TODO [APP-7644]")
}

// UpdateAvailableWiFiNetworks passes the (assumed) most recently available WiFi networks through a channel so that
// they can be written to the BLE characteristic (and thus updated on paired devices which are "provisioning").
func (s *linux) UpdateAvailableWiFiNetworks(awns *AvailableWiFiNetworks) error {
	return errors.New("TODO [APP-7644]")
}

// ReadSsid returns the written ssid value or raises an EmptyBluetoothCharacteristicError error.
func (s *linux) ReadSsid() (string, error) {
	return "", errors.New("TODO [APP-7644]")
}

// ReadPsk returns the written psk value or raises an EmptyBluetoothCharacteristicError error.
func (s *linux) ReadPsk() (string, error) {
	return "", errors.New("TODO [APP-7644]")
}

// ReadRobotPartKeyID returns the written robot part key ID value or raises an EmptyBluetoothCharacteristicError error.
func (s *linux) ReadRobotPartKeyID() (string, error) {
	return "", errors.New("TODO [APP-7644]")
}

// ReadRobotPartKey returns the written robot part key value or raises an EmptyBluetoothCharacteristicError error.
func (s *linux) ReadRobotPartKey() (string, error) {
	return "", errors.New("TODO [APP-7644]")
}

// EmptyBluetoothCharacteristicError represents the error which is raised when we attempt to read from an empty BLE characteristic.
type EmptyBluetoothCharacteristicError struct {
	missingValue string
}

func (e *EmptyBluetoothCharacteristicError) Error() string {
	return fmt.Sprintf("no value has been written to BLE characteristic for %s", e.missingValue)
}
