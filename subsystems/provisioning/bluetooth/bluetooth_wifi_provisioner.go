// Package ble contains an interface for using bluetooth-low-energy to retrieve WiFi and robot part credentials for an unprovisioned Agent.
package ble

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
	"go.viam.com/rdk/logging"
	"go.viam.com/utils"
	"tinygo.org/x/bluetooth"
)

// BluetoothWiFiProvisioner provides an interface for managing the bluetooth (bluetooth-low-energy) service as it pertains to WiFi setup.
type BluetoothWiFiProvisioner interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	RefreshAvailableNetworks(ctx context.Context, awns *AvailableWiFiNetworks) error
	WaitForCredentials(ctx context.Context, requiresCloudCredentials bool, requiresWiFiCredentials bool) (*Credentials, error)
}

// linuxBluetoothWiFiProvisioner provides an interface for managing BLE (bluetooth-low-energy) peripheral advertisement on Linux.
type bluetoothWiFiProvisioner[T bluetoothService] struct {
	svc T
}

// Start begins advertising a bluetooth service that acccepts WiFi and Viam cloud config credentials.
func (bwp *bluetoothWiFiProvisioner[T]) Start(ctx context.Context) error {
	return bm.svc.startAdvertisingBLE(ctx)
}

// Stop stops advertising a bluetooth service which (when enabled) accepts WiFi and Viam cloud config credentials.
func (bwp *bluetoothWiFiProvisioner[T]) Stop(ctx context.Context) error {
	return bwp.s
}

// Update updates the list of networks that are advertised via bluetooth as available.
func (bwp *bluetoothWiFiProvisioner[T]) RefreshAvailableNetworks(ctx context.Context, awns *AvailableWiFiNetworks) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	bwp.svc.
		bm.bleService.s.availableWiFiNetworksChannelWriteOnly <- awns
	bm.bleService.UpdateAvailableWiFiNetworks(awns)
	return nil
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
				ssid, ssidErr = waitForBLEValue(ctx, bm.bleService.ReadSsid, "ssid")
			},
			wg.Done,
		)
		utils.ManagedGo(
			func() {
				psk, pskErr = waitForBLEValue(ctx, bm.bleService.ReadPsk, "psk")
			},
			wg.Done,
		)
	}
	if requiresCloudCredentials {
		wg.Add(2)
		utils.ManagedGo(
			func() {
				robotPartKeyID, robotPartKeyIDErr = waitForBLEValue(ctx, bm.bleService.ReadRobotPartKeyID, "robot part key ID")
			},
			wg.Done,
		)
		utils.ManagedGo(
			func() {
				robotPartKey, robotPartKeyErr = waitForBLEValue(ctx, bm.bleService.ReadRobotPartKey, "robot part key")
			},
			wg.Done,
		)
	}
	wg.Wait()

	return &Credentials{
		Ssid: ssid, Psk: psk, RobotPartKeyID: robotPartKeyID, RobotPartKey: robotPartKey,
	}, multierr.Combine(ssidErr, pskErr, robotPartKeyIDErr, robotPartKeyErr)
}

// credentials represents the minimum required information needed to provision a Viam Agent.
type Credentials struct {
	Ssid           string
	Psk            string
	RobotPartKeyID string
	RobotPartKey   string
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

type bluetoothService interface {
	startAdvertisingBLE(ctx context.Context) error
	stopAdvertisingBLE() error
	writeAvailableNetworks(networks *AvailableWiFiNetworks) error
	readSsid() (string, error)
	readPsk() (string, error)
	readRobotPartKeyID() (string, error)
	readRobotPartKey() (string, error)
}

type linuxBLECharacteristic[T any] struct {
	UUID   bluetooth.UUID
	mu     *sync.Mutex
	active bool // Currently non-functional, but should be used to make characteristics optional.

	currentValue T
}

type linuxBLEService struct {
	logger logging.Logger
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
func newLinuxBLEService(ctx context.Context, logger logging.Logger, name string) (bluetoothService, error) {
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
func (s *linuxBLEService) startAdvertisingBLE(ctx context.Context) error {
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
		if err := listenForPairing(ctx, s.logger); err != nil {
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
func (s *linuxBLEService) stopAdvertisingBLE() error {
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

// readSsid returns the written ssid value or raises an EmptyBluetoothCharacteristicError error.
func (s *linuxBLEService) readSsid() (string, error) {
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

// readPsk returns the written psk value or raises an EmptyBluetoothCharacteristicError error.
func (s *linuxBLEService) readPsk() (string, error) {
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

// readRobotPartKeyID returns the written robot part key ID value or raises an EmptyBluetoothCharacteristicError error.
func (s *linuxBLEService) readRobotPartKeyID() (string, error) {
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

// readRobotPartKey returns the written robot part key value or raises an EmptyBluetoothCharacteristicError error.
func (s *linuxBLEService) readRobotPartKey() (string, error) {
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
