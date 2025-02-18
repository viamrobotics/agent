// Package ble contains an interface for using bluetooth-low-energy to retrieve WiFi and robot part credentials for an unprovisioned Agent.
package ble

import (
	"context"
	"encoding/json"
	"sync"

	"errors"

	"github.com/google/uuid"
	errw "github.com/pkg/errors"
	"go.uber.org/multierr"
	"go.viam.com/rdk/logging"
	"go.viam.com/utils"
	"tinygo.org/x/bluetooth"
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

// linuxBluetoothCharacteristic is used to read and write values to a bluetooh peripheral.
type linuxBluetoothCharacteristic[T any] struct {
	UUID   bluetooth.UUID
	mu     sync.Mutex
	active bool // Currently non-functional, but should be used to make characteristics optional.

	currentValue T
}

// bluetoothWiFiProvisioner provides an interface for managing BLE (bluetooth-low-energy) peripheral advertisement on Linux.
type BluetoothWiFiProvisioner struct {
	logger logging.Logger
	mu     sync.Mutex

	adv       *bluetooth.Advertisement
	advActive bool
	UUID      bluetooth.UUID

	availableWiFiNetworksChannelWriteOnly chan<- *AvailableWiFiNetworks

	characteristicSsid           *linuxBluetoothCharacteristic[*string]
	characteristicPsk            *linuxBluetoothCharacteristic[*string]
	characteristicRobotPartKeyID *linuxBluetoothCharacteristic[*string]
	characteristicRobotPartKey   *linuxBluetoothCharacteristic[*string]
}

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
	return nil
}

func (bwp *BluetoothWiFiProvisioner) stopAdvertisingBLE() error {
	return nil
}

func (bwp *BluetoothWiFiProvisioner) enableAutoAcceptPairRequest() {
}

func (bwp *BluetoothWiFiProvisioner) writeAvailableNetworks(ctx context.Context, networks *AvailableWiFiNetworks) error {
	return nil
}

func (bwp *BluetoothWiFiProvisioner) readSsid() (string, error) {
	return "", nil
}

func (bwp *BluetoothWiFiProvisioner) readPsk() (string, error) {
	return "", nil
}

func (bwp *BluetoothWiFiProvisioner) readRobotPartKeyID() (string, error) {
	return "", nil
}

func (bwp *BluetoothWiFiProvisioner) readRobotPartKey() (string, error) {
	return "", nil
}

// NewBluetoothWiFiProvisioner returns a service which accepts credentials over bluetooth to provision a robot and its WiFi connection.
func NewBluetoothWiFiProvisioner(ctx context.Context, logger logging.Logger, name string) (*BluetoothWiFiProvisioner, error) {
	adapter := bluetooth.DefaultAdapter
	if err := adapter.Enable(); err != nil {
		return nil, errw.WithMessage(err, "failed to enable bluetooth adapter")
	}

	serviceUUID := bluetooth.NewUUID(uuid.New()).Replace16BitComponent(0x1111)
	logger.Infof("serviceUUID: %s", serviceUUID.String())
	charSsidUUID := bluetooth.NewUUID(uuid.New()).Replace16BitComponent(0x2222)
	logger.Infof("charSsidUUID: %s", charSsidUUID.String())
	charPskUUID := bluetooth.NewUUID(uuid.New()).Replace16BitComponent(0x3333)
	logger.Infof("charPskUUID: %s", charPskUUID.String())
	charRobotPartKeyIDUUID := bluetooth.NewUUID(uuid.New()).Replace16BitComponent(0x4444)
	logger.Infof("charRobotPartKeyIDUUID: %s", charRobotPartKeyIDUUID.String())
	charRobotPartKeyUUID := bluetooth.NewUUID(uuid.New()).Replace16BitComponent(0x5555)
	logger.Infof("charRobotPartKeyUUID: %s", charRobotPartKeyUUID.String())
	charAvailableWiFiNetworksUUID := bluetooth.NewUUID(uuid.New()).Replace16BitComponent(0x6666)
	logger.Infof("charAvailableWiFiNetworksUUID: %s", charAvailableWiFiNetworksUUID.String())

	// Create abstracted characteristics which act as a buffer for reading data from bluetooth.
	charSsid := &linuxBluetoothCharacteristic[*string]{
		UUID:         charSsidUUID,
		mu:           sync.Mutex{},
		active:       true,
		currentValue: nil,
	}
	charPsk := &linuxBluetoothCharacteristic[*string]{
		UUID:         charPskUUID,
		mu:           sync.Mutex{},
		active:       true,
		currentValue: nil,
	}
	charRobotPartKeyID := &linuxBluetoothCharacteristic[*string]{
		UUID:         charRobotPartKeyIDUUID,
		mu:           sync.Mutex{},
		active:       true,
		currentValue: nil,
	}
	charRobotPartKey := &linuxBluetoothCharacteristic[*string]{
		UUID:         charRobotPartKeyUUID,
		mu:           sync.Mutex{},
		active:       true,
		currentValue: nil,
	}

	// Create write-only, locking characteristics (one per credential) for fields that are written to.
	charConfigSsid := bluetooth.CharacteristicConfig{
		UUID:  charSsidUUID,
		Flags: bluetooth.CharacteristicWritePermission,
		WriteEvent: func(client bluetooth.Connection, offset int, value []byte) {
			v := string(value)
			logger.Infof("Received SSID: %s", v)
			charSsid.mu.Lock()
			defer charSsid.mu.Unlock()
			charSsid.currentValue = &v
		},
	}
	charConfigPsk := bluetooth.CharacteristicConfig{
		UUID:  charPskUUID,
		Flags: bluetooth.CharacteristicWritePermission,
		WriteEvent: func(client bluetooth.Connection, offset int, value []byte) {
			v := string(value)
			logger.Infof("Received Passkey: %s", v)
			charPsk.mu.Lock()
			defer charPsk.mu.Unlock()
			charPsk.currentValue = &v
		},
	}
	charConfigRobotPartKeyID := bluetooth.CharacteristicConfig{
		UUID:  charRobotPartKeyIDUUID,
		Flags: bluetooth.CharacteristicWritePermission,
		WriteEvent: func(client bluetooth.Connection, offset int, value []byte) {
			v := string(value)
			logger.Infof("Received Robot Part Key ID: %s", v)
			charRobotPartKeyID.mu.Lock()
			defer charRobotPartKeyID.mu.Unlock()
			charRobotPartKeyID.currentValue = &v
		},
	}
	charConfigRobotPartKey := bluetooth.CharacteristicConfig{
		UUID:  charRobotPartKeyUUID,
		Flags: bluetooth.CharacteristicWritePermission,
		WriteEvent: func(client bluetooth.Connection, offset int, value []byte) {
			v := string(value)
			logger.Infof("Received Robot Part Key: %s", v)
			charRobotPartKey.mu.Lock()
			defer charRobotPartKey.mu.Unlock()
			charRobotPartKey.currentValue = &v
		},
	}

	// Create a read-only characteristic for broadcasting nearby, available WiFi networks.
	charConfigAvailableWiFiNetworks := bluetooth.CharacteristicConfig{
		UUID:       charAvailableWiFiNetworksUUID,
		Flags:      bluetooth.CharacteristicReadPermission,
		Value:      nil, // This will get filled in via calls to UpdateAvailableWiFiNetworks.
		WriteEvent: nil, // This characteristic is read-only.
	}

	// Create service which will advertise each of the above characteristics.
	s := &bluetooth.Service{
		UUID: serviceUUID,
		Characteristics: []bluetooth.CharacteristicConfig{
			charConfigSsid,
			charConfigPsk,
			charConfigRobotPartKeyID,
			charConfigRobotPartKey,
			charConfigAvailableWiFiNetworks,
		},
	}
	if err := adapter.AddService(s); err != nil {
		return nil, errw.WithMessage(err, "unable to add bluetooth service to default adapter")
	}
	if err := adapter.Enable(); err != nil {
		return nil, errw.WithMessage(err, "failed to enable bluetooth adapter")
	}
	defaultAdvertisement := adapter.DefaultAdvertisement()
	if defaultAdvertisement == nil {
		return nil, errors.New("default advertisement is nil")
	}
	if err := defaultAdvertisement.Configure(
		bluetooth.AdvertisementOptions{
			LocalName:    name,
			ServiceUUIDs: []bluetooth.UUID{serviceUUID},
		},
	); err != nil {
		return nil, errw.WithMessage(err, "failed to configure default advertisement")
	}
	return &BluetoothWiFiProvisioner{
		logger: logger,
		mu:     sync.Mutex{},

		adv:       defaultAdvertisement,
		advActive: false,
		UUID:      serviceUUID,

		availableWiFiNetworksChannelWriteOnly: nil,

		characteristicSsid:           charSsid,
		characteristicPsk:            charPsk,
		characteristicRobotPartKeyID: charRobotPartKeyID,
		characteristicRobotPartKey:   charRobotPartKey,
	}, nil
}
