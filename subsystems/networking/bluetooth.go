package networking

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
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

const (
	ssidKey                     = "ssid"
	pskKey                      = "psk"
	robotPartKeyIDKey           = "robot_part_key_ID"
	robotPartKeyKey             = "robot_part_key"
	appAddresskey               = "app_address"
	availableWiFiNetworksKey    = "available_WiFi_networks"
	numWriteableCharacteristics = 5
)

// bluetoothService provides an interface for retrieving cloud config and/or WiFi credentials for a robot over bluetooth.
type bluetoothService interface {
	start(ctx context.Context, requiresCloudCredentials, requiresWiFiCredentials bool, inputChat chan<- userInput) error
	stop() error
}

// newBluetoothService returns a service which accepts credentials over bluetooth to provision a robot and its WiFi connection.
func newBluetoothService(
	logger logging.Logger,
	name string,
	getVisibleNetworksFn func() []NetworkInfo,
) (bluetoothService, *health, error) {
	if err := validateSystem(logger); err != nil {
		return nil, nil, fmt.Errorf("cannot initialize bluetooth peripheral, system requisites not met: %w", err)
	}

	var health health

	// Used to manage state of bluez and system D-bus properties.
	var trustedDevices []string
	var bluezAgentRegistered bool
	var listeningForPropertyChanges bool

	// Used to manage state of bluetooth advertisement.
	var adv *bluetooth.Advertisement
	var advActive bool

	bsl := &bluetoothServiceLinux{
		health: &health,

		logger: logger,

		trustedDevices:              trustedDevices,
		bluezAgentRegistered:        bluezAgentRegistered,
		listeningForPropertyChanges: listeningForPropertyChanges,

		adv:       adv,
		advActive: advActive,

		// Used to store user input values written to this bluetooth service.
		characteristicsByName: map[string]*bluetoothCharacteristicLinux[*string]{},
	}

	// Create a bluetooth service which will advertise each of the following characteristics.
	ssidCharacteristicConfig := bsl.getWriteOnlyCharacteristicConfig(ssidKey, 0x2222)
	pskCharacteristicConfig := bsl.getWriteOnlyCharacteristicConfig(pskKey, 0x3333)
	robotPartKeyIDCharacteristicConfig := bsl.getWriteOnlyCharacteristicConfig(robotPartKeyIDKey, 0x4444)
	robotPartKeyCharacteristicConfig := bsl.getWriteOnlyCharacteristicConfig(robotPartKeyKey, 0x5555)
	appAddressCharacteristicConfig := bsl.getWriteOnlyCharacteristicConfig(appAddresskey, 0x6666)
	availableWiFiNetworksCharacteristicConfig := bsl.getReadOnlyCharacteristicConfig(availableWiFiNetworksKey, 0x7777)
	serviceUUID, defaultAdvertisement, err := initializeBluetoothService(
		name,
		[]bluetooth.CharacteristicConfig{
			ssidCharacteristicConfig,
			pskCharacteristicConfig,
			robotPartKeyIDCharacteristicConfig,
			robotPartKeyCharacteristicConfig,
			appAddressCharacteristicConfig,
			availableWiFiNetworksCharacteristicConfig,
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize bluetooth service: %w", err)
	}
	logger.Debugf("Bluetooth peripheral service UUID: %s", serviceUUID.String())

	// Set the bluetooth service default advertisement.
	bsl.adv = defaultAdvertisement

	// Define the function which is used to refresh the available WiFi networks.
	bsl.getVisibleNetworks = getVisibleNetworksFn

	return bsl, &health, nil
}

// bluetoothCharacteristicLinux is used to read and write values to a bluetooth peripheral.
type bluetoothCharacteristicLinux[T any] struct {
	UUID         bluetooth.UUID
	mu           sync.Mutex
	currentValue T
}

// bluetoothServiceLinux provides methods to retrieve cloud config and/or WiFi credentials for a robot over bluetooth.
type bluetoothServiceLinux struct {
	cancel context.CancelFunc
	health *health

	logger logging.Logger

	mu      sync.Mutex
	workers sync.WaitGroup

	trustedDevices                             []string
	bluezAgentRegistered                       bool
	listeningForPropertyChanges                bool
	adv                                        *bluetooth.Advertisement
	advActive                                  bool
	UUID                                       bluetooth.UUID
	getVisibleNetworks                         func() []NetworkInfo
	writeAvailableWiFiNetworksToCharacteristic func(p []byte) (n int, e error)
	characteristicsByName                      map[string]*bluetoothCharacteristicLinux[*string]
}

// Start begins advertising a bluetooth service that advertises nearby networks and acccepts WiFi and/or Viam cloud config credentials.
func (bsl *bluetoothServiceLinux) start(
	parentCtx context.Context,
	requiresCloudCredentials, requiresWiFiCredentials bool,
	inputChan chan<- userInput,
) error {
	bsl.mu.Lock()
	defer bsl.mu.Unlock()

	// Store cancel func on struct for controlled shutdown of goroutines.
	ctx, cancel := context.WithCancel(parentCtx)
	bsl.cancel = cancel

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

	// Start goroutine to listen for updates to list of available WiFi networks.
	bsl.workers.Add(1)
	utils.ManagedGo(
		func() {
			if err := bsl.updateAvailableWiFiNetworks(ctx); err != nil {
				bsl.logger.Errorw("failed to update available WiFi networks", "error", err)
				cancel()
			}
		},
		bsl.workers.Done,
	)

	// Start goroutine to listen for user input.
	bsl.workers.Add(1)
	utils.ManagedGo(
		func() {
			if err := bsl.listenForCredentials(ctx, requiresCloudCredentials, requiresWiFiCredentials, inputChan); err != nil {
				bsl.logger.Errorw("failed to get credentials from user input", "error", err)
			}
			cancel()
		},
		bsl.workers.Done,
	)

	// Start goroutine to listen for bluetooth pairing requests.
	bsl.workers.Add(1)
	utils.ManagedGo(
		func() {
			if err := bsl.autoAcceptPairRequest(ctx); err != nil {
				bsl.logger.Errorw("failed to enable auto accept of bluetooth pairing requests", "error", err)
				cancel()
			}
		},
		bsl.workers.Done,
	)

	return nil
}

// Stop stops advertising a bluetooth service which (when enabled) accepts WiFi and Viam cloud config credentials.
func (bsl *bluetoothServiceLinux) stop() error {
	bsl.mu.Lock()
	defer bsl.mu.Unlock()

	bsl.logger.Debug("Canceling bluetooth service context for clean shutdown.")
	bsl.cancel()

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

	// Cleanly shut down all goroutines.
	bsl.workers.Wait()

	return nil
}

/** Helper method(s) for low-level system calls and read/write requests to/from bluetooth characteristics **/

// read returns a string value that was written to a bluetooth characteristic by a client.
func (bsl *bluetoothServiceLinux) getCharacteristic(c string) (string, error) {
	if bsl.characteristicsByName == nil {
		return "", errors.New("characteristics map is empty")
	}
	ch, ok := bsl.characteristicsByName[c]
	if !ok {
		return "", fmt.Errorf("characteristic %s does not exist", c)
	}
	ch.mu.Lock()
	defer ch.mu.Unlock()

	// Use pointers so we can distinguish between receiving empty strings and receiving nothing.
	if ch.currentValue == nil {
		return "", newEmptyBluetoothCharacteristicError(c)
	}
	return *ch.currentValue, nil
}

// updateAvailableWiFiNetworks writes currently-available WiFi networks to a read-only bluetooth characteristic once per second.
func (bsl *bluetoothServiceLinux) updateAvailableWiFiNetworks(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if !bsl.health.Sleep(ctx, time.Second*5) {
				return ctx.Err()
			}
			networks := bsl.getVisibleNetworks()
			bs, err := json.Marshal(networks)
			if err != nil {
				return err
			}

			// Chunking writes to a maximum of 20 bytes because BLE characteristics can only accept 20 bytes per message.
			chunkSize := 20
			for {
				if len(bs) <= chunkSize {
					_, err = bsl.writeAvailableWiFiNetworksToCharacteristic(bs)
					if err != nil {
						return err
					}
					break
				}
				if _, err = bsl.writeAvailableWiFiNetworksToCharacteristic(bs[:chunkSize]); err != nil {
					return err
				}
				bs = bs[chunkSize:]
			}
			bsl.logger.Info("Successfully updated visible WiFi networks.")
		}
	}
}

// listenForCredentials returns credentials, the minimum required information to provision a robot and/or its WiFi.
func (bsl *bluetoothServiceLinux) listenForCredentials(
	ctx context.Context, requiresCloudCredentials, requiresWiFiCredentials bool, inputChan chan<- userInput,
) error {
	if !requiresWiFiCredentials && !requiresCloudCredentials {
		return errors.New("should be waiting for cloud credentials or WiFi credentials, or both")
	}
	var ssid, psk, robotPartKeyID, robotPartKey, appAdress string
	var ssidErr, pskErr, robotPartKeyIDErr, robotPartKeyErr, appAddressErr error
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if requiresWiFiCredentials {
				if ssid == "" {
					var e *emptyBluetoothCharacteristicError
					ssid, ssidErr = bsl.getCharacteristic(ssidKey)
					if ssidErr != nil && !errors.As(ssidErr, &e) {
						return ssidErr
					}
				}
				if psk == "" {
					var e *emptyBluetoothCharacteristicError
					psk, pskErr = bsl.getCharacteristic(pskKey)
					if pskErr != nil && !errors.As(pskErr, &e) {
						return pskErr
					}
				}
			}
			if requiresCloudCredentials {
				if robotPartKeyID == "" {
					var e *emptyBluetoothCharacteristicError
					robotPartKeyID, robotPartKeyIDErr = bsl.getCharacteristic(robotPartKeyIDKey)
					if robotPartKeyIDErr != nil && !errors.As(robotPartKeyIDErr, &e) {
						return robotPartKeyIDErr
					}
				}
				if robotPartKey == "" {
					var e *emptyBluetoothCharacteristicError
					robotPartKey, robotPartKeyErr = bsl.getCharacteristic(robotPartKeyKey)
					if robotPartKeyErr != nil && !errors.As(robotPartKeyErr, &e) {
						return robotPartKeyErr
					}
				}
				if appAdress == "" {
					var e *emptyBluetoothCharacteristicError
					appAdress, appAddressErr = bsl.getCharacteristic(appAddresskey)
					if appAddressErr != nil && !errors.As(appAddressErr, &e) {
						return appAddressErr
					}
				}
			}
			if requiresWiFiCredentials && requiresCloudCredentials && //nolint:gocritic
				ssid != "" && psk != "" && robotPartKeyID != "" && robotPartKey != "" && appAdress != "" {
				break
			} else if requiresWiFiCredentials && ssid != "" && psk != "" {
				break
			} else if requiresCloudCredentials && robotPartKeyID != "" && robotPartKey != "" && appAdress != "" {
				break
			}
			if !bsl.health.Sleep(ctx, time.Second) {
				return ctx.Err()
			}
			continue
		}
		inputChan <- userInput{SSID: ssid, PSK: psk, PartID: robotPartKeyID, Secret: robotPartKey, AppAddr: appAdress}
		return nil
	}
}

/** Custom error type and miscellaneous utils that are helpful for managing low-level bluetooth on Linux **/

// initializeBluetoothService performs low-level system configuration to enable bluetooth advertisement.
func initializeBluetoothService(deviceName string, characteristics []bluetooth.CharacteristicConfig,
) (bluetooth.UUID, *bluetooth.Advertisement, error) {
	adapter := bluetooth.DefaultAdapter
	if err := adapter.Enable(); err != nil {
		return [4]uint32{}, nil, fmt.Errorf("failed to enable bluetooth adapter: %w", err)
	}
	serviceUUID := bluetooth.NewUUID(uuid.New()).Replace16BitComponent(0x1111)
	if err := adapter.AddService(
		&bluetooth.Service{
			UUID:            serviceUUID,
			Characteristics: characteristics,
		},
	); err != nil {
		return [4]uint32{}, nil, fmt.Errorf("unable to add bluetooth service to default adapter: %w", err)
	}
	if err := adapter.Enable(); err != nil {
		return [4]uint32{}, nil, fmt.Errorf("failed to enable bluetooth adapter: %w", err)
	}
	defaultAdvertisement := adapter.DefaultAdvertisement()
	if defaultAdvertisement == nil {
		return [4]uint32{}, nil, errors.New("default advertisement is nil")
	}
	if err := defaultAdvertisement.Configure(
		bluetooth.AdvertisementOptions{
			LocalName:    deviceName,
			ServiceUUIDs: []bluetooth.UUID{serviceUUID},
		},
	); err != nil {
		return [4]uint32{}, nil, fmt.Errorf("failed to configure default advertisement: %w", err)
	}
	return serviceUUID, defaultAdvertisement, nil
}

// getWriteOnlyCharacteristicConfig returns a bluetooth characteristic config and wrapper type for accessing written values.
func (bsl *bluetoothServiceLinux) getWriteOnlyCharacteristicConfig(cName string, encoding uint16,
) bluetooth.CharacteristicConfig {
	cUUID := bluetooth.NewUUID(uuid.New()).Replace16BitComponent(encoding)
	bsl.logger.Debugf("%s can be written to the following bluetooth characteristic: %s", cName, cUUID.String())
	characteristic := &bluetoothCharacteristicLinux[*string]{
		UUID:         cUUID,
		currentValue: nil,
	}
	bsl.characteristicsByName[cName] = characteristic
	return bluetooth.CharacteristicConfig{
		UUID:  cUUID,
		Flags: bluetooth.CharacteristicWritePermission,
		WriteEvent: func(client bluetooth.Connection, offset int, value []byte) {
			v := string(value)
			bsl.logger.Infof("Received %s: %s from client with connection ID: %d", cName, v, client)
			characteristic.mu.Lock()
			defer characteristic.mu.Unlock()
			characteristic.currentValue = &v
		},
	}
}

// getReadOnlyCharacteristicConfig returns a bluetooth characteristic config and function for internally updating the read-only value.
func (bsl *bluetoothServiceLinux) getReadOnlyCharacteristicConfig(cName string, encoding uint16) bluetooth.CharacteristicConfig {
	cUUID := bluetooth.NewUUID(uuid.New()).Replace16BitComponent(encoding)
	bsl.logger.Debugf("%s can be read from the following bluetooth characteristic: %s", cName, cUUID.String())
	c := &bluetooth.Characteristic{}
	bsl.writeAvailableWiFiNetworksToCharacteristic = c.Write
	return bluetooth.CharacteristicConfig{
		Handle: c,
		UUID:   cUUID,
		Flags:  bluetooth.CharacteristicReadPermission,
	}
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

// validateSystem checks BlueZ installation/version.
func validateSystem(logger logging.Logger) error {
	// 1. Check BlueZ version
	blueZVersion, err := getBlueZVersion()
	if err != nil {
		return err
	}

	// 2. Validate BlueZ version is 5.66 or higher
	if blueZVersion < 5.66 {
		return fmt.Errorf("BlueZ version is %.2f, but 5.66 or later is required", blueZVersion)
	}

	logger.Debugf("BlueZ version (%.2f) meets the requirement (5.66 or later)", blueZVersion)
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

// autoAccceptPairRequest ensures this device automatically accepts bluetooth pairing requests.
func (bsl *bluetoothServiceLinux) autoAcceptPairRequest(ctx context.Context) error {
	conn, err := dbus.SystemBus()
	if err != nil {
		return fmt.Errorf("failed to connect to system DBus: %w", err)
	}
	if err := bsl.registerBluezAgent(conn); err != nil {
		return err
	}
	if err := bsl.listenForPropertyChanges(conn); err != nil {
		return err
	}

	// Listen for properties changed events (includes bluetooth pairing requests).
	signalChan := make(chan *dbus.Signal, 25)
	conn.Signal(signalChan)
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case signal := <-signalChan:
			if signal == nil || signal.Body == nil {
				continue
			}
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
			return bsl.trustDevice(devicePath)
		default:
			if !bsl.health.Sleep(ctx, time.Second) {
				return ctx.Err()
			}
		}
	}
}

// registerBluezAgent registers the bluez agent via the system D bus.
func (bsl *bluetoothServiceLinux) registerBluezAgent(conn *dbus.Conn) error {
	bsl.mu.Lock()
	defer bsl.mu.Unlock()

	if bsl.bluezAgentRegistered {
		bsl.logger.Debug("Bluez agent is already registered.")
		return nil
	}

	// Export agent methods
	reply := conn.Export(nil, BluezAgentPath, BluezAgent)
	if reply != nil {
		return fmt.Errorf("failed to export Bluez agent: %w", reply)
	}

	// Register the agent.
	obj := conn.Object(BluezDBusService, "/org/bluez")
	call := obj.Call("org.bluez.AgentManager1.RegisterAgent", 0, dbus.ObjectPath(BluezAgentPath), "NoInputNoOutput")
	if err := call.Err; err != nil {
		return fmt.Errorf("failed to register Bluez agent: %w", err)
	}

	// Set as the default agent
	call = obj.Call("org.bluez.AgentManager1.RequestDefaultAgent", 0, dbus.ObjectPath(BluezAgentPath))
	if err := call.Err; err != nil {
		return fmt.Errorf("failed to set default Bluez agent: %w", err)
	}

	bsl.logger.Debug("Bluez agent registered!")
	bsl.bluezAgentRegistered = true

	return nil
}

// listenForPropertyChanges begins listening for bluetooth pairing requests on the system D-bus.
func (bsl *bluetoothServiceLinux) listenForPropertyChanges(conn *dbus.Conn) error {
	bsl.mu.Lock()
	defer bsl.mu.Unlock()

	if bsl.listeningForPropertyChanges {
		bsl.logger.Debug("Already listening for property changes (bluetooth pairing requests) on the system D-bus.")
		return nil
	}

	matchRule := "type='signal',interface='org.freedesktop.DBus.Properties',member='PropertiesChanged'"
	err := conn.BusObject().Call("org.freedesktop.DBus.AddMatch", 0, matchRule).Err
	if err != nil {
		return fmt.Errorf("failed to add DBus match rule: %w", err)
	}

	bsl.listeningForPropertyChanges = true
	bsl.logger.Debug("Listening for property changes (bluetooth pairing requests) on system D-bus.")

	return nil
}

// trustDevice sets the device as trusted and connects to it.
func (bsl *bluetoothServiceLinux) trustDevice(devicePath string) error {
	bsl.mu.Lock()
	defer bsl.mu.Unlock()

	for _, trustedDevice := range bsl.trustedDevices {
		if trustedDevice == devicePath {
			bsl.logger.Debugf("Device: %s is already trusted", devicePath)
			return nil
		}
	}

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
	bsl.trustedDevices = append(bsl.trustedDevices, devicePath)
	bsl.logger.Debugf("Device: %s marked as trusted.", devicePath)

	return nil
}
