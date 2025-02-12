// Package ble contains an interface for interacting with the bluetooth stack on a Linux device, specifically with respect to provisioning.
package ble

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/edaniels/golog"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"go.viam.com/utils"
	"tinygo.org/x/bluetooth"
)

type BLEService interface {
	StartAdvertising(ctx context.Context) error
	StopAdvertising() error
	UpdateAvailableWiFiNetworks(awns *AvailableWiFiNetworks)
	ReadSsid() (string, error)
	ReadPsk() (string, error)
	ReadRobotPartKeyID() (string, error)
	ReadRobotPartKey() (string, error)
}

type AvailableWiFiNetworks struct {
	Networks []*struct {
		Ssid        string  `json:"ssid"`
		Strength    float64 `json:"strength"` // This float, in the inclusive range [0.0, 1.0], represents the % strength of a WiFi network.
		RequiresPsk bool    `json:"requires_psk"`
	} `json:"networks"`
}

func (awns *AvailableWiFiNetworks) ToBytes() ([]byte, error) {
	return json.Marshal(awns)
}

type linuxBLECharacteristic[T any] struct {
	UUID   bluetooth.UUID
	mu     *sync.Mutex
	active bool // Currently non-functional, but should be used to make characteristics optional.

	currentValue T
}

type linuxBLEService struct {
	logger golog.Logger
	mu     *sync.Mutex

	adv       *bluetooth.Advertisement
	advActive bool
	UUID      bluetooth.UUID

	availableWiFiNetworksChannelWriteOnly chan<- *AvailableWiFiNetworks

	characteristicSsid           *linuxBLECharacteristic[*string]
	characteristicPsk            *linuxBLECharacteristic[*string]
	characteristicRobotPartKeyID *linuxBLECharacteristic[*string]
	characteristicRobotPartKey   *linuxBLECharacteristic[*string]
}

// NewLinuxBLEService returns a bluetooth-low-energy service that advertises writeable characteristics for WiFi and robot part credentials,
// and a separate readable characteristic for the most recently available WiFi networks near the unprovisioned device.
func NewLinuxBLEService(ctx context.Context, logger golog.Logger, name string) (BLEService, error) {
	if err := validateSystem(logger); err != nil {
		return nil, errors.WithMessage(err, "cannot initialize bluetooth peripheral, system requisites not met")
	}

	adapter := bluetooth.DefaultAdapter
	if err := adapter.Enable(); err != nil {
		return nil, errors.WithMessage(err, "failed to enable bluetooth adapter")
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
	charSsid := &linuxBLECharacteristic[*string]{
		UUID:         charSsidUUID,
		mu:           &sync.Mutex{},
		active:       true,
		currentValue: nil,
	}
	charPsk := &linuxBLECharacteristic[*string]{
		UUID:         charPskUUID,
		mu:           &sync.Mutex{},
		active:       true,
		currentValue: nil,
	}
	charRobotPartKeyID := &linuxBLECharacteristic[*string]{
		UUID:         charRobotPartKeyIDUUID,
		mu:           &sync.Mutex{},
		active:       true,
		currentValue: nil,
	}
	charRobotPartKey := &linuxBLECharacteristic[*string]{
		UUID:         charRobotPartKeyUUID,
		mu:           &sync.Mutex{},
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

	// Channel will be written to by interface method UpdateAvailableWiFiNetworks and will be read by
	// the following background goroutine
	availableWiFiNetworksChannel := make(chan *AvailableWiFiNetworks, 1)

	// Read only channel used to listen for updates to the availableWiFiNetworks.
	var availableWiFiNetworksChannelReadOnly <-chan *AvailableWiFiNetworks = availableWiFiNetworksChannel
	utils.ManagedGo(func() {
		for {
			if err := ctx.Err(); err != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			case awns := <-availableWiFiNetworksChannelReadOnly:
				bs, err := awns.ToBytes()
				if err != nil {
					logger.Errorw("failed to cast available WiFi networks to bytes before writing to bluetooth characteristic")
				}
				charConfigAvailableWiFiNetworks.Value = bs
				logger.Infow("successfully updated available WiFi networks on bluetooth characteristic")
			default:
				time.Sleep(time.Second)
			}
		}
	}, nil)

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
		return nil, errors.WithMessage(err, "unable to add bluetooth service to default adapter")
	}
	if err := adapter.Enable(); err != nil {
		return nil, errors.WithMessage(err, "failed to enable bluetooth adapter")
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
		return nil, errors.WithMessage(err, "failed to configure default advertisement")
	}
	return &linuxBLEService{
		logger: logger,
		mu:     &sync.Mutex{},

		adv:       defaultAdvertisement,
		advActive: false,
		UUID:      serviceUUID,

		availableWiFiNetworksChannelWriteOnly: availableWiFiNetworksChannel,

		characteristicSsid:           charSsid,
		characteristicPsk:            charPsk,
		characteristicRobotPartKeyID: charRobotPartKeyID,
		characteristicRobotPartKey:   charRobotPartKey,
	}, nil
}

// StartAdvertising begins advertising a BLE service.
func (s *linuxBLEService) StartAdvertising(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.adv == nil {
		return errors.New("advertisement is nil")
	}
	if s.advActive {
		return errors.New("invalid request, advertising already active")
	}
	if err := s.adv.Start(); err != nil {
		return errors.WithMessage(err, "failed to start advertising")
	}
	utils.ManagedGo(func() {
		if err := listenForPairing(s.logger); err != nil {
			s.logger.Errorw(
				"failed to listen for pairing request (will have to manually accept pairing request on device)",
				"err", err)
		}
	}, nil)
	s.advActive = true
	s.logger.Info("started advertising a BLE connection...")
	return nil
}

// StopAdvertising stops advertising a BLE service.
func (s *linuxBLEService) StopAdvertising() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.adv == nil {
		return errors.New("advertisement is nil")
	}
	if !s.advActive {
		return errors.New("invalid request, advertising already inactive")
	}
	if err := s.adv.Stop(); err != nil {
		return errors.WithMessage(err, "failed to stop advertising")
	}
	s.advActive = false
	s.logger.Info("stopped advertising a BLE connection")
	return nil
}

// UpdateAvailableWiFiNetworks passes the (assumed) most recently available WiFi networks through a channel so that
// they can be written to the BLE characteristic (and thus updated on paired devices which are "provisioning").
func (s *linuxBLEService) UpdateAvailableWiFiNetworks(awns *AvailableWiFiNetworks) {
	s.availableWiFiNetworksChannelWriteOnly <- awns
}

// EmptyBluetoothCharacteristicError represents the error which is raised when we attempt to read from an empty BLE characteristic.
type EmptyBluetoothCharacteristicError struct {
	missingValue string
}

func (e *EmptyBluetoothCharacteristicError) Error() string {
	return fmt.Sprintf("No value has been written to BLE characteristic for %s", e.missingValue)
}

func newEmptyBluetoothCharacteristicError(missingValue string) error {
	return &EmptyBluetoothCharacteristicError{
		missingValue: missingValue,
	}
}

// ReadSsid returns the written ssid value or raises an EmptyBluetoothCharacteristicError error.
func (s *linuxBLEService) ReadSsid() (string, error) {
	if s.characteristicSsid == nil {
		return "", errors.New("characteristic ssid is nil")
	}

	s.characteristicSsid.mu.Lock()
	defer s.characteristicSsid.mu.Unlock()

	if !s.characteristicSsid.active {
		return "", errors.New("characteristic ssid is inactive")
	}
	if s.characteristicSsid.currentValue == nil {
		return "", newEmptyBluetoothCharacteristicError("ssid")
	}
	return *s.characteristicSsid.currentValue, nil
}

// ReadPsk returns the written psk value or raises an EmptyBluetoothCharacteristicError error.
func (s *linuxBLEService) ReadPsk() (string, error) {
	if s.characteristicPsk == nil {
		return "", errors.New("characteristic psk is nil")
	}

	s.characteristicPsk.mu.Lock()
	defer s.characteristicPsk.mu.Unlock()

	if !s.characteristicPsk.active {
		return "", errors.New("characteristic psk is inactive")
	}
	if s.characteristicPsk.currentValue == nil {
		return "", newEmptyBluetoothCharacteristicError("psk")
	}
	return *s.characteristicPsk.currentValue, nil
}

// ReadRobotPartKeyID returns the written robot part key ID value or raises an EmptyBluetoothCharacteristicError error.
func (s *linuxBLEService) ReadRobotPartKeyID() (string, error) {
	if s.characteristicRobotPartKeyID == nil {
		return "", errors.New("characteristic robot part key ID is nil")
	}

	s.characteristicRobotPartKeyID.mu.Lock()
	defer s.characteristicRobotPartKeyID.mu.Unlock()

	if !s.characteristicRobotPartKeyID.active {
		return "", errors.New("characteristic robot part key ID is inactive")
	}
	if s.characteristicRobotPartKeyID.currentValue == nil {
		return "", newEmptyBluetoothCharacteristicError("robot part key ID")
	}
	return *s.characteristicRobotPartKeyID.currentValue, nil
}

// ReadRobotPartKey returns the written robot part key value or raises an EmptyBluetoothCharacteristicError error.
func (s *linuxBLEService) ReadRobotPartKey() (string, error) {
	if s.characteristicRobotPartKey == nil {
		return "", errors.New("characteristic robot part key is nil")
	}

	s.characteristicRobotPartKey.mu.Lock()
	defer s.characteristicRobotPartKey.mu.Unlock()

	if !s.characteristicRobotPartKey.active {
		return "", errors.New("characteristic robot part key is inactive")
	}
	if s.characteristicRobotPartKey.currentValue == nil {
		return "", newEmptyBluetoothCharacteristicError("robot part key")
	}
	return *s.characteristicRobotPartKey.currentValue, nil
}
