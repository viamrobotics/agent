package networking

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"slices"
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
	ssidKey                  = "SSID"
	pskKey                   = "PSK"
	robotPartKeyIDKey        = "Robot Part Key ID"
	robotPartKeyKey          = "Robot Part Key"
	appAddressKey            = "App Address"
	availableWiFiNetworksKey = "Available WiFi Networks"
)

// bluetoothService provides an interface for retrieving cloud config and/or WiFi credentials for a machine over bluetooth.
type bluetoothService interface {
	start(ctx context.Context, requiresCloudCredentials, requiresWiFiCredentials bool, inputChat chan<- userInput) error
	stop() error
	getHealth() bool
}

// bluetoothCharacteristicLinux is used to read and write values to a bluetooth peripheral.
type bluetoothCharacteristicLinux[T any] struct {
	UUID         bluetooth.UUID
	mu           sync.Mutex
	currentValue T
}

// bluetoothServiceLinux provides methods to retrieve cloud config and/or WiFi credentials for a robot over bluetooth.
type bluetoothServiceLinux struct {
	mu         sync.Mutex
	workers    sync.WaitGroup
	logger     logging.Logger
	deviceName string
	cancelFunc context.CancelFunc

	// Store health for entire bluetooth service.
	healthMu sync.Mutex
	health   bool

	// Allow healthy sleeping in each asynchronous goroutine in the bluetooth service.
	updateAvailableWiFiNetworksHealth *health
	listenForCredentialsHealth        *health
	listenForPairRequestHealth        *health

	// Stopping/restarting an existing bluetooth service requires the following state variables.
	trustedDevices              []string
	bluezAgentRegistered        bool
	listeningForPropertyChanges bool
	adv                         *bluetooth.Advertisement
	advActive                   bool
	characteristicsByName       map[string]*bluetoothCharacteristicLinux[*string]

	// Below callback functions are used to retrieve visible networks and to write that list of available networks to
	// a bluetooth characteristic. The bluetooth characteristic, "Available WiFi Networks", is read-only from the
	// perspective of a client.
	requestAvailableWiFiNetworks func() []NetworkInfo
	refreshAvailableWiFiNetworks func(p []byte) (e error)
}

// newBluetoothService returns a service which accepts credentials over bluetooth to provision a robot and its WiFi connection.
func newBluetoothService(
	logger logging.Logger,
	deviceName string,
	requestAvailableWiFiNetworksFn func() []NetworkInfo,
) (bluetoothService, error) {
	if err := validateSystem(logger); err != nil {
		return nil, fmt.Errorf("system requisites not met: %w", err)
	}
	if deviceName == "" {
		return nil, errors.New("must provide a device name")
	}
	if requestAvailableWiFiNetworksFn == nil {
		return nil, errors.New("must provide function which returns available WiFi networks")
	}

	// Used to store and manage state around Bluez system configuration.
	var trustedDevices []string
	var bluezAgentRegistered bool
	var listeningForPropertyChanges bool

	// Used to manage state of bluetooth advertisement.
	var adv *bluetooth.Advertisement
	var advActive bool

	bsl := &bluetoothServiceLinux{
		deviceName: deviceName,
		logger:     logger,

		trustedDevices:              trustedDevices,
		bluezAgentRegistered:        bluezAgentRegistered,
		listeningForPropertyChanges: listeningForPropertyChanges,

		adv:       adv,
		advActive: advActive,

		// Used to store user input values written to this bluetooth service.
		characteristicsByName: map[string]*bluetoothCharacteristicLinux[*string]{},

		// Used to refresh the available WiFi networks.
		requestAvailableWiFiNetworks: requestAvailableWiFiNetworksFn,
	}

	return bsl, nil
}


// Start begins advertising a bluetooth service that advertises nearby networks and acccepts WiFi and/or Viam cloud config credentials.
func (bsl *bluetoothServiceLinux) start(
	ctx context.Context,
	requiresCloudCredentials, requiresWiFiCredentials bool,
	inputChan chan<- userInput,
) error {
	bsl.mu.Lock()
	defer bsl.mu.Unlock()

	if err := bsl.prepare(); err != nil {
		return err
	}
	bsl.run(ctx, requiresCloudCredentials, requiresWiFiCredentials, inputChan)

	return nil
}

// stop stops advertising a bluetooth service which (when enabled) accepts WiFi and Viam cloud config credentials.
func (bsl *bluetoothServiceLinux) stop() error {
	bsl.mu.Lock()
	defer bsl.mu.Unlock()

	if !bsl.advActive {
		return errors.New("invalid request, advertising already inactive")
	}
	if bsl.adv == nil {
		return errors.New("advertisement is nil")
	}
	if err := bsl.adv.Stop(); err != nil {
		return fmt.Errorf("failed to stop advertising: %w", err)
	}
	bsl.advActive = false
	bsl.logger.Debug("Stopped advertising bluetooth service.")

	bsl.cancelFunc()
	bsl.workers.Wait()
	return nil
}

// ---------------------------------------------------------------------------------------
// ---------------------------------- INTERNAL METHODS -----------------------------------
// ---------------------------------------------------------------------------------------

// getHealth returns true if each of the bluetooth services are in a good state.
func (bsl *bluetoothServiceLinux) getHealth() bool {
	bsl.healthMu.Lock()
	defer bsl.healthMu.Unlock()
	return bsl.health
}

// setHealth sets the bluetooth service health.
func (bsl *bluetoothServiceLinux) setHealth(h bool) {
	bsl.healthMu.Lock()
	defer bsl.healthMu.Unlock()
	bsl.health = h
}

// prepare initializes bluetooth services and defines in-memory state for storing user input.
func (bsl *bluetoothServiceLinux) prepare() error {
	if bsl.advActive {
		return errors.New("invalid request, advertising already active")
	}

	// Define each of the following characteristics in memory (and return their associated configs)
	ssidCharacteristicConfig := initializeWriteOnlyBluetoothCharacteristic(bsl, ssidKey, 0x2222)
	pskCharacteristicConfig := initializeWriteOnlyBluetoothCharacteristic(bsl, pskKey, 0x3333)
	robotPartKeyIDCharacteristicConfig := initializeWriteOnlyBluetoothCharacteristic(bsl, robotPartKeyIDKey, 0x4444)
	robotPartKeyCharacteristicConfig := initializeWriteOnlyBluetoothCharacteristic(bsl, robotPartKeyKey, 0x5555)
	appAddressCharacteristicConfig := initializeWriteOnlyBluetoothCharacteristic(bsl, appAddressKey, 0x6666)
	availableWiFiNetworksCharacteristicConfig := initializeReadOnlyBluetoothCharacteristic(bsl, availableWiFiNetworksKey, 0x7777)

	// Create a bluetooth service comprised of the above configs.
	serviceUUID, defaultAdvertisement, err := initializeBluetoothService(
		bsl.deviceName,
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
		return fmt.Errorf("failed to initialize bluetooth service: %w", err)
	}

	// Start advertising the bluetooth service.
	if err := defaultAdvertisement.Start(); err != nil {
		return fmt.Errorf("failed to start advertising: %w", err)
	}
	bsl.advActive = true
	bsl.adv = defaultAdvertisement
	bsl.logger.Debugf("Started advertising bluetooth service with UUID: %s.", serviceUUID.String())

	return nil
}

// run spawns three goroutines, one to refresh available WiFi networks, another to listen for user input, and the last to listen for bluetooth
// pairing requests.
func (bsl *bluetoothServiceLinux) run(ctx context.Context, requiresCloudCredentials, requiresWiFiCredentials bool, inputChan chan<- userInput) {
	ctx, cancel := context.WithCancel(ctx)
	bsl.setHealth(true)

	// Create shared context with cancelation to control goroutines.
	bsl.cancelFunc = cancel

	// Start goroutine to update the list of available WiFi networks.
	bsl.workers.Add(1)
	utils.ManagedGo(
		func() {
			if err := updateAvailableWiFiNetworks(ctx, bsl); err != nil {
				bsl.logger.Errorw("failed to update available WiFi networks", "error", err)
				bsl.setHealth(false)

				// Only cancel on failures. Failures indicate we've hit some exception and are
				// unable to write the latest, available WiFi networks to our bluetooth service.
				bsl.cancelFunc()
			}
		},
		bsl.workers.Done,
	)

	// Start goroutine to listen for user input.
	bsl.workers.Add(1)
	utils.ManagedGo(
		func() {
			// Cancel on failures or successes. The goal is to terminate goroutines once we've received
			// the minimum required set of credentials (cloud, network, or both) from user input.
			defer bsl.cancelFunc()

			if err := listenForCredentials(ctx, bsl, requiresCloudCredentials, requiresWiFiCredentials, inputChan); err != nil {
				bsl.logger.Errorw("failed to get credentials from user input", "error", err)
				bsl.setHealth(false)
			}
		},
		bsl.workers.Done,
	)

	// Start goroutine to listen for bluetooth pairing requests.
	bsl.workers.Add(1)
	utils.ManagedGo(
		func() {
			if err := bsl.listenForPairRequest(ctx); err != nil {
				bsl.logger.Errorw("failed to enable auto accept of bluetooth pairing requests", "error", err)
				bsl.setHealth(false)

				// Only cancel on failures. It will return early if we've already "turned on" auto-accept in a
				// preceding call to run. This happens if we've started provisioning, stopped, and
				// ultimately started once more. This is difficult to handle because we make system-level
				// configuration changes to the Bluez configuration on a device which don't "go away" after
				// provisioning ends.
				bsl.cancelFunc()
			}
		},
		bsl.workers.Done,
	)
}

// ---------------------------------------------------------------------------------------
// --------------------------------------- HELPERS ---------------------------------------
// ---------------------------------------------------------------------------------------

// read returns a string value that was written to a bluetooth characteristic by a client.
func readCharacteristic(bsl *bluetoothServiceLinux, c string) (string, error) {
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
func updateAvailableWiFiNetworks(ctx context.Context, bsl *bluetoothServiceLinux) error {
	if bsl.updateAvailableWiFiNetworksHealth != nil {
		return errors.New("failed to start updating available WiFi networks, updates are already in progress")
	}
	h := &health{}
	h.MarkGood()
	bsl.updateAvailableWiFiNetworksHealth = h

	for {
		networks := bsl.requestAvailableWiFiNetworks()
		bs, err := json.Marshal(networks)
		if err != nil {
			return err
		}

		// Chunking writes to a maximum of 512 bytes because BLE characteristics can only accept 512 bytes per message.
		chunkSize := 512
		for {
			if len(bs) <= chunkSize {
				if err := bsl.refreshAvailableWiFiNetworks(bs); err != nil {
					return err
				}
				break
			} else {
				if err := bsl.refreshAvailableWiFiNetworks(bs[:chunkSize]); err != nil {
					return err
				}
				bs = bs[chunkSize:]
			}
		}
		if !bsl.updateAvailableWiFiNetworksHealth.Sleep(ctx, time.Second*5) {
			return ctx.Err()
		}
	}
}

// listenForCredentials returns credentials, the minimum required information to provision a robot and/or its WiFi.
func listenForCredentials(ctx context.Context, bsl *bluetoothServiceLinux, requiresCloudCredentials,
	requiresWiFiCredentials bool, inputChan chan<- userInput,
) error {
	if !requiresWiFiCredentials && !requiresCloudCredentials {
		return errors.New("should be waiting for cloud credentials or WiFi credentials, or both")
	}
	if bsl.listenForCredentialsHealth != nil {
		return errors.New("failed to start listening for credentials, listener already in progress")
	}
	h := &health{}
	h.MarkGood()
	bsl.listenForCredentialsHealth = h

	var ssid, psk, robotPartKeyID, robotPartKey, appAddress string
	var e *emptyBluetoothCharacteristicError
	for {
		// If new values are provided, persist them to in-memory storage.
		if requiresWiFiCredentials {
			ssidInput, ssidErr := readCharacteristic(bsl, ssidKey)
			if ssidErr != nil && !errors.As(ssidErr, &e) {
				return ssidErr
			}
			if ssidInput != "" && ssidInput != ssid {
				ssid = ssidInput
			}
			pskInput, pskErr := readCharacteristic(bsl, pskKey)
			if pskErr != nil && !errors.As(pskErr, &e) {
				return pskErr
			}
			if pskInput != "" && pskInput != psk {
				psk = pskInput
			}
		}
		if requiresCloudCredentials {
			robotPartKeyIDInput, robotPartKeyIDErr := readCharacteristic(bsl, robotPartKeyIDKey)
			if robotPartKeyIDErr != nil && !errors.As(robotPartKeyIDErr, &e) {
				return robotPartKeyIDErr
			}
			if robotPartKeyIDInput != "" && robotPartKeyIDInput != robotPartKeyID {
				robotPartKeyID = robotPartKeyIDInput
			}
			robotPartKeyInput, robotPartKeyErr := readCharacteristic(bsl, robotPartKeyKey)
			if robotPartKeyErr != nil && !errors.As(robotPartKeyErr, &e) {
				return robotPartKeyErr
			}
			if robotPartKeyInput != "" && robotPartKeyInput != robotPartKey {
				robotPartKey = robotPartKeyInput
			}
			appAddressInput, appAddressErr := readCharacteristic(bsl, appAddressKey)
			if appAddressErr != nil && !errors.As(appAddressErr, &e) {
				return appAddressErr
			}
			if appAddressInput != "" && appAddressInput != appAddress {
				appAddress = appAddressInput
			}
		}

		// If we've received all required credentials, break to pass them through inputChan.
		if requiresWiFiCredentials && requiresCloudCredentials && //nolint:gocritic
			ssid != "" && psk != "" && robotPartKeyID != "" && robotPartKey != "" && appAddress != "" {
			break
		} else if requiresWiFiCredentials && ssid != "" && psk != "" {
			break
		} else if requiresCloudCredentials && robotPartKeyID != "" && robotPartKey != "" && appAddress != "" {
			break
		}

		// If we haven't received all required credentials, try again a second later.
		if !bsl.listenForCredentialsHealth.Sleep(ctx, time.Second) {
			return ctx.Err()
		}
		continue

	}
	inputChan <- userInput{SSID: ssid, PSK: psk, PartID: robotPartKeyID, Secret: robotPartKey, AppAddr: appAddress}
	return nil
}

// initializeWriteOnlyBluetoothCharacteristic returns a bluetooth characteristic config.
func initializeWriteOnlyBluetoothCharacteristic(bsl *bluetoothServiceLinux, cName string, encoding uint16,
) bluetooth.CharacteristicConfig {
	cUUID := bluetooth.NewUUID(uuid.New()).Replace16BitComponent(encoding)
	bsl.logger.Debugf("%s can be written to the following bluetooth characteristic: %s", cName, cUUID.String())

	// characteristic represents the in-memory storage for the characteristic identifiable by cName.
	characteristic := &bluetoothCharacteristicLinux[*string]{
		UUID:         cUUID,
		currentValue: nil,
	}
	bsl.characteristicsByName[cName] = characteristic

	return bluetooth.CharacteristicConfig{
		UUID:  cUUID,
		Flags: bluetooth.CharacteristicWritePermission,

		// WriteEvent is defined by the bluetooth package and is the callback function which handles
		// write events to bluetooth characteristics. Once written, it is our job to "save" these
		// values to in-memory storage.
		WriteEvent: func(client bluetooth.Connection, offset int, value []byte) {
			v := string(value)
			bsl.logger.Infof("Received %s: %s from client with connection ID: %d", cName, v, client)

			// Mutex locks each characteristic that is being written so simultaneous calls to
			// bsl.readCharacteristic(cName) safely access the characteristic value.
			characteristic.mu.Lock()
			defer characteristic.mu.Unlock()
			characteristic.currentValue = &v
		},
	}
}

// initializeReadOnlyBluetoothCharacteristic returns a bluetooth characteristic config.
func initializeReadOnlyBluetoothCharacteristic(bsl *bluetoothServiceLinux, cName string, encoding uint16) bluetooth.CharacteristicConfig {
	cUUID := bluetooth.NewUUID(uuid.New()).Replace16BitComponent(encoding)
	bsl.logger.Debugf("%s can be read from the following bluetooth characteristic: %s", cName, cUUID.String())
	c := &bluetooth.Characteristic{}

	// refreshAvailableWiFiNetworks represents the callback function used
	// to dynamically update an otherwise read-only bluetooth characteristic.
	bsl.refreshAvailableWiFiNetworks = func(bs []byte) error {
		_, err := c.Write(bs)
		return err
	}
	return bluetooth.CharacteristicConfig{
		Handle: c,
		UUID:   cUUID,
		Flags:  bluetooth.CharacteristicReadPermission,
	}
}

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

// emptyBluetoothCharacteristicError represents the error which is raised when we attempt to read from an empty BLE characteristic.
type emptyBluetoothCharacteristicError struct {
	missingValue string
}

func (e *emptyBluetoothCharacteristicError) Error() string {
	return fmt.Sprintf("no value has been written to bluetooth characteristic for %s", e.missingValue)
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
func (bsl *bluetoothServiceLinux) listenForPairRequest(ctx context.Context) error {
	if bsl.listenForPairRequestHealth != nil {
		return errors.New("failed to start listening for pair request, listener already in progress")
	}
	h := &health{}
	h.MarkGood()
	bsl.listenForPairRequestHealth = h

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
			if !bsl.listenForPairRequestHealth.Sleep(ctx, time.Second) {
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

	if slices.Contains(bsl.trustedDevices, devicePath) {
		bsl.logger.Debugf("Device: %s is already trusted", devicePath)
		return nil
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
