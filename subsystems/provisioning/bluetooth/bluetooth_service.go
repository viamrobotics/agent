// Package ble contains an interface for interacting with the bluetooth stack on a Linux device, specifically with respect to provisioning.
package ble

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"go.viam.com/rdk/logging"
	"go.viam.com/utils"
)

type bluetoothService interface {
	startAdvertisingBLE(ctx context.Context) error
	stopAdvertisingBLE() error
	enableAutoAcceptPairRequest()

	// Available WiFi networks need to be written to a bluetooth service. Clients read from this inputted data.
	writeAvailableNetworks(networks *AvailableWiFiNetworks) error

	// Credentials that are written by a client need to be extracted from a bluetooth service.
	readSsid() (string, error)
	readPsk() (string, error)
	readRobotPartKeyID() (string, error)
	readRobotPartKey() (string, error)
}

// linuxBluetoothCharacteristic is used to read and write values to a bluetooh peripheral.
type linuxBluetoothCharacteristic[T any] struct {
	UUID   bluetooth.UUID
	mu     *sync.Mutex
	active bool // Currently non-functional, but should be used to make characteristics optional.

	currentValue T
}

// linuxBluetoothService represents the linux implementation of a bluetooth service for provisioning.
type linuxBluetoothService struct {
	logger logging.Logger
	mu     *sync.Mutex

	adv       *bluetooth.Advertisement
	advActive bool
	UUID      bluetooth.UUID

	availableWiFiNetworksChannelWriteOnly chan<- *AvailableWiFiNetworks

	characteristicSsid           *linuxBluetoothCharacteristic[*string]
	characteristicPsk            *linuxBluetoothCharacteristic[*string]
	characteristicRobotPartKeyID *linuxBluetoothCharacteristic[*string]
	characteristicRobotPartKey   *linuxBluetoothCharacteristic[*string]
}

// NewlinuxBluetoothService returns a bluetooth-low-energy service that advertises writeable characteristics for WiFi and robot part credentials,
// and a separate readable characteristic for the most recently available WiFi networks near the unprovisioned device.
func newlinuxBluetoothService(ctx context.Context, logger logging.Logger, name string) (bluetoothService, error) {
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
	charSsid := &linuxBluetoothCharacteristic[*string]{
		UUID:         charSsidUUID,
		mu:           &sync.Mutex{},
		active:       true,
		currentValue: nil,
	}
	charPsk := &linuxBluetoothCharacteristic[*string]{
		UUID:         charPskUUID,
		mu:           &sync.Mutex{},
		active:       true,
		currentValue: nil,
	}
	charRobotPartKeyID := &linuxBluetoothCharacteristic[*string]{
		UUID:         charRobotPartKeyIDUUID,
		mu:           &sync.Mutex{},
		active:       true,
		currentValue: nil,
	}
	charRobotPartKey := &linuxBluetoothCharacteristic[*string]{
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
		defer close(availableWiFiNetworksChannel)
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
	return &linuxBluetoothService{
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
func (s *linuxBluetoothService) startAdvertisingBLE(ctx context.Context) error {
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
	s.advActive = true
	s.logger.Info("started advertising a BLE connection...")
	return nil
}

// listenForPairing spins off an asynch goroutine which waits for an incoming BLE pairing request and automatically trusts the device.
func (s *linuxBluetoothService) enableAutoAcceptPairRequest() {
	var err error
	utils.ManagedGo(func() {
		conn, err := dbus.SystemBus()
		if err != nil {
			err = errors.WithMessage(err, "failed to connect to system DBus")
			return
		}

		// Export agent methods
		reply := conn.Export(nil, BluezAgentPath, BluezAgent)
		if reply != nil {
			err = errors.WithMessage(reply, "failed to export Bluez agent")
			return
		}

		// Register the agent
		obj := conn.Object(BluezDBusService, "/org/bluez")
		call := obj.Call("org.bluez.AgentManager1.RegisterAgent", 0, dbus.ObjectPath(BluezAgentPath), "NoInputNoOutput")
		if err := call.Err; err != nil {
			err = errors.WithMessage(err, "failed to register Bluez agent")
			return
		}

		// Set as the default agent
		call = obj.Call("org.bluez.AgentManager1.RequestDefaultAgent", 0, dbus.ObjectPath(BluezAgentPath))
		if err := call.Err; err != nil {
			err = errors.WithMessage(err, "failed to set default Bluez agent")
			return
		}

		s.logger.Info("Bluez agent registered!")

		// Listen for properties changed events
		signalChan := make(chan *dbus.Signal, 10)
		conn.Signal(signalChan)

		// Add a match rule to listen for DBus property changes
		matchRule := "type='signal',interface='org.freedesktop.DBus.Properties',member='PropertiesChanged'"
		err = conn.BusObject().Call("org.freedesktop.DBus.AddMatch", 0, matchRule).Err
		if err != nil {
			err = errors.WithMessage(err, "failed to add DBus match rule")
			return
		}

		s.logger.Info("waiting for a BLE pairing request...")

		for signal := range signalChan {
			// Check if the signal is from a BlueZ device
			if len(signal.Body) < 3 {
				continue
			}

			iface, ok := signal.Body[0].(string)
			if !ok || iface != "org.bluez.Device1" {
				continue
			}

			// Check if the "Paired" property is in the event
			changedProps, ok := signal.Body[1].(map[string]dbus.Variant)
			if !ok {
				continue
			}

			// TODO [APP-7613]: Pairing attempts from an iPhone connect first
			// before pairing, so listen for a "Connected" event on the system
			// D-Bus. This should be tested against Android.
			connected, exists := changedProps["Connected"]
			if !exists || connected.Value() != true {
				continue
			}

			// Extract device path from the signal sender
			devicePath := string(signal.Path)

			// Convert DBus object path to MAC address
			deviceMAC := convertDBusPathToMAC(devicePath)
			if deviceMAC == "" {
				continue
			}

			s.logger.Infof("device %s initiated pairing!", deviceMAC)

			// Mark device as trusted
			if err = trustDevice(s.logger, devicePath); err != nil {
				err = errors.WithMessage(err, "failed to trust device")
				return
			} else {
				s.logger.Info("device successfully trusted!")
			}
		}
	}, nil)
	if err != nil {
		s.logger.Errorw(
			"failed to listen for pairing request (will have to manually accept pairing request on device)",
			"err", err)
	}
}

// StopAdvertising stops advertising a BLE service.
func (s *linuxBluetoothService) stopAdvertisingBLE() error {
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

// writeAvailableWiFiNetworks passes WiFi networks which are accessible to the device over bluetooth.
func (s *linuxBluetoothService) writeAvailableNetworks(awns *AvailableWiFiNetworks) error {
	s.availableWiFiNetworksChannelWriteOnly <- awns
	return nil
}

// readSsid returns the written ssid value or raises an EmptyBluetoothCharacteristicError error.
func (s *linuxBluetoothService) readSsid() (string, error) {
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
func (s *linuxBluetoothService) readPsk() (string, error) {
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
func (s *linuxBluetoothService) readRobotPartKeyID() (string, error) {
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
func (s *linuxBluetoothService) readRobotPartKey() (string, error) {
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

const (
	BluezDBusService  = "org.bluez"
	BluezAgentPath    = "/custom/agent"
	BluezAgentManager = "org.bluez.AgentManager1"
	BluezAgent        = "org.bluez.Agent1"
)

// checkOS verifies the system is running a Linux distribution.
func checkOS() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("this program requires Linux, detected: %s", runtime.GOOS)
	}
	return nil
}

// getBlueZVersion retrieves the installed BlueZ version and extracts the numeric value correctly.
func getBlueZVersion() (float64, error) {
	// Try to get version from bluetoothctl first, fallback to bluetoothd
	versionCmds := []string{"bluetoothctl --version", "bluetoothd --version"}

	var versionOutput bytes.Buffer
	var err error

	for _, cmd := range versionCmds {
		versionOutput.Reset() // Clear buffer
		cmdParts := strings.Fields(cmd)
		execCmd := exec.Command(cmdParts[0], cmdParts[1:]...) //nolint:gosec
		execCmd.Stdout = &versionOutput
		err = execCmd.Run()
		if err == nil {
			break // Found a valid command
		}
	}

	if err != nil {
		return 0, fmt.Errorf("BlueZ is not installed or not accessible")
	}

	// Extract only the numeric version
	versionStr := strings.TrimSpace(versionOutput.String())
	parts := strings.Fields(versionStr)

	// Ensure we have at least one part before accessing it
	if len(parts) == 0 {
		return 0, fmt.Errorf("failed to parse BlueZ version: empty output")
	}

	versionNum := parts[len(parts)-1] // Get the last word, which should be the version number

	// Convert to float
	versionFloat, err := strconv.ParseFloat(versionNum, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse BlueZ version: %s", versionStr)
	}

	return versionFloat, nil
}

// validateSystem checks OS and BlueZ installation/version.
func validateSystem(logger logging.Logger) error {
	// 1. Validate OS
	if err := checkOS(); err != nil {
		return err
	}
	logger.Info("✅ Running on a Linux system.")

	// 2. Check BlueZ version
	blueZVersion, err := getBlueZVersion()
	if err != nil {
		return err
	}
	logger.Infof("✅ BlueZ detected, version: %.2f", blueZVersion)

	// 3. Validate BlueZ version is 5.66 or higher
	if blueZVersion < 5.66 {
		return fmt.Errorf("❌ BlueZ version is %.2f, but 5.66 or later is required", blueZVersion)
	}

	logger.Info("✅ BlueZ version meets the requirement (5.66 or later).")
	return nil
}

// trustDevice sets the device as trusted and connects to it.
func trustDevice(logger logging.Logger, devicePath string) error {
	conn, err := dbus.SystemBus()
	if err != nil {
		return fmt.Errorf("failed to connect to DBus: %w", err)
	}

	obj := conn.Object(BluezDBusService, dbus.ObjectPath(devicePath))

	// Set Trusted = true
	call := obj.Call("org.freedesktop.DBus.Properties.Set", 0,
		"org.bluez.Device1", "Trusted", dbus.MakeVariant(true))
	if call.Err != nil {
		return fmt.Errorf("failed to set Trusted property: %w", call.Err)
	}
	logger.Info("device marked as trusted.")

	return nil
}

// convertDBusPathToMAC converts a DBus object path to a Bluetooth MAC address.
func convertDBusPathToMAC(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) < 4 {
		return ""
	}

	// Extract last part and convert underscores to colons
	macPart := parts[len(parts)-1]
	mac := strings.ReplaceAll(macPart, "_", ":")
	return mac
}
