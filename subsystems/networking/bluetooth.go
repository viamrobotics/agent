package networking

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/godbus/dbus"
	"github.com/google/uuid"
	"go.viam.com/rdk/logging"
	"go.viam.com/utils"
	"tinygo.org/x/bluetooth"
)

// bluetoothService provides an interface for retrieving cloud config and/or WiFi credentials for a robot over bluetooth.
type bluetoothService interface {
	start(ctx context.Context) error
	stop() error
	waitForCredentials(ctx context.Context, requiresCloudCredentials, requiresWiFiCredentials bool, inputChan chan<- userInput) error
}

// newBluetoothService returns a service which accepts credentials over bluetooth to provision a robot and its WiFi connection.
func newBluetoothService(logger logging.Logger, name string, availableNetworks []NetworkInfo,
) (bluetoothService, error) {
	if err := validateSystem(logger); err != nil {
		return nil, fmt.Errorf("cannot initialize bluetooth peripheral, system requisites not met: %w", err)
	}

	adapter := bluetooth.DefaultAdapter
	if err := adapter.Enable(); err != nil {
		return nil, fmt.Errorf("failed to enable bluetooth adapter: %w", err)
	}

	serviceUUID := bluetooth.NewUUID(uuid.New()).Replace16BitComponent(0x1111)
	logger.Debugf("Bluetooth peripheral service UUID: %s", serviceUUID.String())
	charSsidUUID := bluetooth.NewUUID(uuid.New()).Replace16BitComponent(0x2222)
	logger.Debugf("WiFi SSID can be written to the following bluetooth characteristic: %s", charSsidUUID.String())
	charPskUUID := bluetooth.NewUUID(uuid.New()).Replace16BitComponent(0x3333)
	logger.Debugf("WiFi passkey can be written to the following bluetooth characteristic: %s", charPskUUID.String())
	charRobotPartKeyIDUUID := bluetooth.NewUUID(uuid.New()).Replace16BitComponent(0x4444)
	logger.Debugf("Robot part key ID can be written to the following bluetooth characteristic: %s", charRobotPartKeyIDUUID.String())
	charRobotPartKeyUUID := bluetooth.NewUUID(uuid.New()).Replace16BitComponent(0x5555)
	logger.Debugf("Robot part key can be written to the following bluetooth characteristic: %s", charRobotPartKeyUUID.String())
	charAppAddressUUID := bluetooth.NewUUID(uuid.New()).Replace16BitComponent(0x6666)
	logger.Debugf("Viam app address can be written to the following bluetooth characteristic: %s", charAppAddressUUID.String())
	charAvailableWiFiNetworksUUID := bluetooth.NewUUID(uuid.New()).Replace16BitComponent(0x7777)
	logger.Debugf("Available WiFi networks can be read from the following bluetooth characteristic: %s",
		charAvailableWiFiNetworksUUID.String())

	// Create abstracted characteristics which act as a buffer for reading data from bluetooth.
	charSsid := &bluetoothCharacteristicLinux[*string]{
		UUID:         charSsidUUID,
		mu:           &sync.Mutex{},
		currentValue: nil,
	}
	charPsk := &bluetoothCharacteristicLinux[*string]{
		UUID:         charPskUUID,
		mu:           &sync.Mutex{},
		currentValue: nil,
	}
	charRobotPartKeyID := &bluetoothCharacteristicLinux[*string]{
		UUID:         charRobotPartKeyIDUUID,
		mu:           &sync.Mutex{},
		currentValue: nil,
	}
	charRobotPartKey := &bluetoothCharacteristicLinux[*string]{
		UUID:         charRobotPartKeyUUID,
		mu:           &sync.Mutex{},
		currentValue: nil,
	}
	charAppAddress := &bluetoothCharacteristicLinux[*string]{
		UUID:         charAppAddressUUID,
		mu:           &sync.Mutex{},
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
	charConfigAppAddress := bluetooth.CharacteristicConfig{
		UUID:  charAppAddressUUID,
		Flags: bluetooth.CharacteristicWritePermission,
		WriteEvent: func(client bluetooth.Connection, offset int, value []byte) {
			v := string(value)
			logger.Infof("Received App Address: %s", v)
			charAppAddress.mu.Lock()
			defer charAppAddress.mu.Unlock()
			charAppAddress.currentValue = &v
		},
	}

	// Create a read-only characteristic for broadcasting nearby, available WiFi networks.
	var availableNetworksBytes [][]byte
	for _, availableNetwork := range availableNetworks {
		an := NetworkInfo{ // Compress each network by taking only relevant fields.
			SSID:     availableNetwork.SSID,
			Security: availableNetwork.Security,
			Signal:   availableNetwork.Signal,
		}
		bs, err := json.Marshal(an)
		if err != nil {
			logger.Warnf("failed to parse network info: %+v", err)
		}
		availableNetworksBytes = append(availableNetworksBytes, bs)
	}
	charConfigAvailableWiFiNetworks := bluetooth.CharacteristicConfig{
		UUID:  charAvailableWiFiNetworksUUID,
		Flags: bluetooth.CharacteristicReadPermission,
		Value: bytes.Join(availableNetworksBytes, []byte(",")), // Only 20 bytes maximum size,
		// and anything over that gets cut off. This is a BLE characteristic default standard,
		// so we pass in available networks sorted in descending order of signal strength.
	}

	// Create service which will advertise each of the above characteristics.
	s := &bluetooth.Service{
		UUID: serviceUUID,
		Characteristics: []bluetooth.CharacteristicConfig{
			charConfigSsid,
			charConfigPsk,
			charConfigRobotPartKeyID,
			charConfigRobotPartKey,
			charConfigAppAddress,
			charConfigAvailableWiFiNetworks,
		},
	}
	if err := adapter.AddService(s); err != nil {
		return nil, fmt.Errorf("unable to add bluetooth service to default adapter: %w", err)
	}
	if err := adapter.Enable(); err != nil {
		return nil, fmt.Errorf("failed to enable bluetooth adapter: %w", err)
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
		return nil, fmt.Errorf("failed to configure default advertisement: %w", err)
	}
	return &bluetoothServiceLinux{
		logger: logger,
		mu:     &sync.Mutex{},

		adv:       defaultAdvertisement,
		advActive: false,
		UUID:      serviceUUID,

		characteristicSsid:           charSsid,
		characteristicPsk:            charPsk,
		characteristicRobotPartKeyID: charRobotPartKeyID,
		characteristicRobotPartKey:   charRobotPartKey,
		characteristicAppAddress:     charAppAddress,
	}, nil
}

// bluetoothCharacteristicLinux is used to read and write values to a bluetooth peripheral.
type bluetoothCharacteristicLinux[T any] struct {
	UUID bluetooth.UUID
	mu   *sync.Mutex

	currentValue T
}

// bluetoothServiceLinux provides methods to retrieve cloud config and/or WiFi credentials for a robot over bluetooth.
type bluetoothServiceLinux struct {
	logger logging.Logger
	mu     *sync.Mutex

	adv       *bluetooth.Advertisement
	advActive bool
	UUID      bluetooth.UUID

	characteristicSsid           *bluetoothCharacteristicLinux[*string]
	characteristicPsk            *bluetoothCharacteristicLinux[*string]
	characteristicRobotPartKeyID *bluetoothCharacteristicLinux[*string]
	characteristicRobotPartKey   *bluetoothCharacteristicLinux[*string]
	characteristicAppAddress     *bluetoothCharacteristicLinux[*string]
}

// Start begins advertising a bluetooth service that acccepts WiFi and Viam cloud config credentials.
func (bsl *bluetoothServiceLinux) start(ctx context.Context) error {
	bsl.mu.Lock()
	defer bsl.mu.Unlock()
	defer enableAutoAcceptPairRequest(bsl.logger) // Async (logs instead of error checks) to auto-accept pair requests on this device.

	if bsl.adv == nil {
		return errors.New("advertisement is nil")
	}
	if bsl.advActive {
		return errors.New("invalid request, advertising already active")
	}
	if err := bsl.adv.Start(); err != nil {
		return fmt.Errorf("failed to start advertising: %w", err)
	}
	bsl.advActive = true
	bsl.logger.Debug("Started advertising a BLE connection")
	return nil
}

// Stop stops advertising a bluetooth service which (when enabled) accepts WiFi and Viam cloud config credentials.
func (bsl *bluetoothServiceLinux) stop() error {
	bsl.mu.Lock()
	defer bsl.mu.Unlock()

	if bsl.adv == nil {
		return errors.New("advertisement is nil")
	}
	if !bsl.advActive {
		return errors.New("invalid request, advertising already inactive")
	}
	if err := bsl.adv.Stop(); err != nil {
		return fmt.Errorf("failed to stop advertising: %w", err)
	}
	bsl.advActive = false
	bsl.logger.Debug("Stopped advertising a BLE connection")
	return nil
}

// WaitForCredentials returns credentials, the minimum required information to provision a robot and/or its WiFi.
func (bsl *bluetoothServiceLinux) waitForCredentials(
	ctx context.Context, requiresCloudCredentials, requiresWiFiCredentials bool, inputChan chan<- userInput,
) error {
	if !requiresWiFiCredentials && !requiresCloudCredentials {
		return errors.New("should be waiting for cloud credentials or WiFi credentials, or both")
	}
	var ssid, psk, robotPartKeyID, robotPartKey string
	var ssidErr, pskErr, robotPartKeyIDErr, robotPartKeyErr error
	for {
		var shouldBreakOuterLoop bool
		if ctx.Err() != nil {
			shouldBreakOuterLoop = true
			break
		}
		select {
		case <-ctx.Done():
			shouldBreakOuterLoop = true
		default:
			if requiresWiFiCredentials {
				if ssid == "" {
					var e *emptyBluetoothCharacteristicError
					ssid, ssidErr = bsl.readSsid()
					if ssidErr != nil && !errors.As(ssidErr, &e) {
						shouldBreakOuterLoop = true
						break
					}
				}
				if psk == "" {
					var e *emptyBluetoothCharacteristicError
					psk, pskErr = bsl.readPsk()
					if pskErr != nil && !errors.As(pskErr, &e) {
						shouldBreakOuterLoop = true
						break
					}
				}
			}
			if requiresCloudCredentials {
				if robotPartKeyID == "" {
					var e *emptyBluetoothCharacteristicError
					robotPartKeyID, robotPartKeyIDErr = bsl.readRobotPartKeyID()
					if robotPartKeyIDErr != nil && !errors.As(robotPartKeyIDErr, &e) {
						shouldBreakOuterLoop = true
						break
					}
				}
				if robotPartKey == "" {
					var e *emptyBluetoothCharacteristicError
					robotPartKey, robotPartKeyErr = bsl.readRobotPartKey()
					if robotPartKeyErr != nil && !errors.As(robotPartKeyErr, &e) {
						shouldBreakOuterLoop = true
						break
					}
				}
			}
			if requiresWiFiCredentials && requiresCloudCredentials && //nolint:gocritic
				ssid != "" && psk != "" && robotPartKeyID != "" && robotPartKey != "" {
				shouldBreakOuterLoop = true
				break
			} else if requiresWiFiCredentials && ssid != "" && psk != "" {
				shouldBreakOuterLoop = true
				break
			} else if requiresCloudCredentials && robotPartKeyID != "" && robotPartKey != "" {
				shouldBreakOuterLoop = true
				break
			}

			// Not ready to return (do not have the minimum required set of credentials), so sleep and try again.
			time.Sleep(time.Second)
		}
		if shouldBreakOuterLoop {
			break
		}
	}
	if err := errors.Join(ctx.Err(), ssidErr, pskErr, robotPartKeyIDErr, robotPartKeyErr); err != nil {
		return err
	}
	inputChan <- userInput{
		SSID: ssid, PSK: psk, PartID: robotPartKeyID, Secret: robotPartKey,
	}
	return nil
}

/** Helper methods for low-level system calls and read/write requests to/from bluetooth characteristics **/

func (bsl *bluetoothServiceLinux) readSsid() (string, error) {
	if bsl.characteristicSsid == nil {
		return "", errors.New("characteristic ssid is nil")
	}

	bsl.characteristicSsid.mu.Lock()
	defer bsl.characteristicSsid.mu.Unlock()

	if bsl.characteristicSsid.currentValue == nil {
		return "", newEmptyBluetoothCharacteristicError("ssid")
	}
	return *bsl.characteristicSsid.currentValue, nil
}

func (bsl *bluetoothServiceLinux) readPsk() (string, error) {
	if bsl.characteristicPsk == nil {
		return "", errors.New("characteristic psk is nil")
	}

	bsl.characteristicPsk.mu.Lock()
	defer bsl.characteristicPsk.mu.Unlock()

	if bsl.characteristicPsk.currentValue == nil {
		return "", newEmptyBluetoothCharacteristicError("psk")
	}
	return *bsl.characteristicPsk.currentValue, nil
}

func (bsl *bluetoothServiceLinux) readRobotPartKeyID() (string, error) {
	if bsl.characteristicRobotPartKeyID == nil {
		return "", errors.New("characteristic robot part key ID is nil")
	}

	bsl.characteristicRobotPartKeyID.mu.Lock()
	defer bsl.characteristicRobotPartKeyID.mu.Unlock()

	if bsl.characteristicRobotPartKeyID.currentValue == nil {
		return "", newEmptyBluetoothCharacteristicError("robot part key ID")
	}
	return *bsl.characteristicRobotPartKeyID.currentValue, nil
}

func (bsl *bluetoothServiceLinux) readRobotPartKey() (string, error) {
	if bsl.characteristicRobotPartKey == nil {
		return "", errors.New("characteristic robot part key is nil")
	}

	bsl.characteristicRobotPartKey.mu.Lock()
	defer bsl.characteristicRobotPartKey.mu.Unlock()

	if bsl.characteristicRobotPartKey.currentValue == nil {
		return "", newEmptyBluetoothCharacteristicError("robot part key")
	}
	return *bsl.characteristicRobotPartKey.currentValue, nil
}

/** Custom error type and miscellaneous utils that are helpful for managing low-level bluetooth on Linux **/

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

	// 2. Check BlueZ version
	blueZVersion, err := getBlueZVersion()
	if err != nil {
		return err
	}

	// 3. Validate BlueZ version is 5.66 or higher
	if blueZVersion < 5.66 {
		return fmt.Errorf("BlueZ version is %.2f, but 5.66 or later is required", blueZVersion)
	}

	logger.Debugf("BlueZ version (%.2f) meets the requirement (5.66 or later)", blueZVersion)
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
	logger.Debug("Device marked as trusted.")

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

func enableAutoAcceptPairRequest(logger logging.Logger) {
	utils.ManagedGo(func() {
		conn, err := dbus.SystemBus()
		if err != nil {
			logger.Errorf("Failed to connect to system DBus: %w", err)
			return
		}

		// Export agent methods
		reply := conn.Export(nil, BluezAgentPath, BluezAgent)
		if reply != nil {
			logger.Errorf("Failed to export Bluez agent: %w", reply)
			return
		}

		// Register the agent (and defer call to unregister agent).
		obj := conn.Object(BluezDBusService, "/org/bluez")
		call := obj.Call("org.bluez.AgentManager1.RegisterAgent", 0, dbus.ObjectPath(BluezAgentPath), "NoInputNoOutput")
		if err := call.Err; err != nil {
			logger.Errorf("Failed to register Bluez agent: %w", err)
			return
		}
		defer func() {
			call := obj.Call("org.bluez.AgentManager1.UnregisterAgent", 0, dbus.ObjectPath(BluezAgentPath))
			if err := call.Err; err != nil {
				logger.Errorf("Failed to unregister Bluez agent: %w", err)
				return
			}
		}()

		// Set as the default agent
		call = obj.Call("org.bluez.AgentManager1.RequestDefaultAgent", 0, dbus.ObjectPath(BluezAgentPath))
		if err := call.Err; err != nil {
			logger.Errorf("Failed to set default Bluez agent: %w", err)
			return
		}

		logger.Debug("Bluez agent registered!")

		// Listen for properties changed events
		signalChan := make(chan *dbus.Signal, 10)
		conn.Signal(signalChan)

		// Add a match rule to listen for DBus property changes
		matchRule := "type='signal',interface='org.freedesktop.DBus.Properties',member='PropertiesChanged'"
		err = conn.BusObject().Call("org.freedesktop.DBus.AddMatch", 0, matchRule).Err
		if err != nil {
			logger.Errorf("Failed to add DBus match rule: %w", err)
			return
		}

		logger.Debug("Waiting for a BLE pairing request...")

		for signal := range signalChan {
			// Check if the signal is from a BlueZ device
			if len(signal.Body) < 3 {
				continue
			}

			iface, ok := signal.Body[0].(string)
			if !ok || iface != "org.bleuez.Device1" {
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
			if err = trustDevice(logger, devicePath); err != nil {
				logger.Errorf("Failed to trust device: %w", err)
				return
			} else {
				logger.Debug("Device successfully trusted!")
			}
		}
	}, nil)
}
