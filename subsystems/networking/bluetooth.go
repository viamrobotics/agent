package networking

import (
	"bytes"
	"context"
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
	healthy() bool
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

	// Channel remains open until we have successfully completed provisioning.
	provisioningComplete chan struct{}
}

// newBluetoothService returns a service which accepts credentials over bluetooth to provision a robot and its WiFi connection.
func newBluetoothService(
	logger logging.Logger,
	deviceName string,
	requestAvailableWiFiNetworksFn func() []NetworkInfo,
) (bluetoothService, error) {
	if err := validateBlueZVersion(); err != nil {
		return nil, fmt.Errorf("system requisites not met: %+w", err)
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

		// Used to manage whether provisioning completes successfully.
		provisioningComplete: make(chan struct{}),
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
	if err := bsl.run(ctx, requiresCloudCredentials, requiresWiFiCredentials, inputChan); err != nil {
		return err
	}

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

func (bsl *bluetoothServiceLinux) healthy() bool {
	bsl.mu.Lock()
	defer bsl.mu.Unlock()

	return !bsl.advActive || // If we are not advertising, we're healthy (nothing to check).

		(bsl.updateAvailableWiFiNetworksHealth.IsHealthy() && // Otherwise, return combined health of goroutines.
			bsl.listenForCredentialsHealth.IsHealthy() &&
			bsl.listenForPairRequestHealth.IsHealthy())
}

// ---------------------------------------------------------------------------------------
// ---------------------------------- INTERNAL METHODS -----------------------------------
// ---------------------------------------------------------------------------------------

// prepare initializes bluetooth services and defines in-memory state for storing user input.
func (bsl *bluetoothServiceLinux) prepare() error {
	// Can only call this function if the bsl.mu is already locked!

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

// run spawns three goroutines, one to refresh available WiFi networks, another to listen for
// user input, and the last to listen for bluetooth pairing requests.
func (bsl *bluetoothServiceLinux) run(
	ctx context.Context, requiresCloudCredentials, requiresWiFiCredentials bool, inputChan chan<- userInput,
) error {
	// Can only call this function if the bsl.mu is already locked!

	ctx, cancel := context.WithCancel(ctx)
	bsl.cancelFunc = cancel

	// Initialize health for each goroutine.
	h := &health{}
	h.MarkGood()
	bsl.updateAvailableWiFiNetworksHealth = h
	h = &health{}
	h.MarkGood()
	bsl.listenForCredentialsHealth = h
	h = &health{}
	h.MarkGood()
	bsl.listenForPairRequestHealth = h

	// Start goroutine to update the list of available WiFi networks.
	bsl.workers.Add(1)
	utils.ManagedGo(
		func() {
			if err := updateAvailableWiFiNetworks(ctx, bsl); err != nil {
				bsl.logger.Errorw("failed to update available WiFi networks", "error", err)
				bsl.updateAvailableWiFiNetworksHealth.MarkBad()

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
			if err := listenForCredentials(ctx, bsl, requiresCloudCredentials, requiresWiFiCredentials, inputChan); err != nil {
				bsl.logger.Errorw("failed to get credentials from user input", "error", err)
				bsl.listenForCredentialsHealth.MarkBad()

				// Only cancel on failures. Failures indicate we've hit some exception and are
				// unable to accept user input.
				bsl.cancelFunc()
			}
		},
		bsl.workers.Done,
	)

	// Start goroutine to listen for bluetooth pairing requests.
	bsl.workers.Add(1)
	utils.ManagedGo(
		func() {
			if err := listenForPairRequest(ctx, bsl); err != nil {
				bsl.logger.Errorw("failed to enable auto accept of bluetooth pairing requests", "error", err)
				bsl.listenForPairRequestHealth.MarkBad()

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

	return nil
}

// ---------------------------------------------------------------------------------------
// --------------------------------------- HELPERS ---------------------------------------
// ---------------------------------------------------------------------------------------

// updateAvailableWiFiNetworks writes currently-available WiFi networks to a read-only bluetooth characteristic once per second.
func updateAvailableWiFiNetworks(ctx context.Context, bsl *bluetoothServiceLinux) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-bsl.provisioningComplete:
			return nil
		default:
			networks := bsl.requestAvailableWiFiNetworks()

			// Writes are capped at a maximum of 512 bytes (bluetooth-low-energy protocol defines this behavior).
			var msg []byte
			remainingBytes := 512
			for _, network := range networks {
				// Can convert network
				var signal uint8
				if network.Signal > 127 {
					continue // Shouldn't happen, but skipping to avoid integer overflow conversion int32 -> int8.
				}
				signal = uint8(network.Signal) //nolint:gosec
				ssid, secure := network.SSID, network.Security
				meta := signal
				if secure != "" {
					meta |= (1 << 7)
				}
				compressedNetwork := []byte{meta}
				compressedNetwork = append(compressedNetwork, []byte(ssid)...)
				compressedNetwork = append(compressedNetwork, 0x0)

				// Add to msg buffer if we have space. Otherwise, break from loop.
				if l := len(compressedNetwork); remainingBytes >= l {
					msg = append(msg, compressedNetwork...)
					remainingBytes -= l
					continue
				}
				break
			}
			if err := bsl.refreshAvailableWiFiNetworks(msg); err != nil {
				return err
			}
			if !bsl.updateAvailableWiFiNetworksHealth.Sleep(ctx, time.Second*10) {
				return ctx.Err()
			}
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
		} else if requiresWiFiCredentials && !requiresCloudCredentials && ssid != "" && psk != "" {
			break
		} else if requiresCloudCredentials && !requiresWiFiCredentials && robotPartKeyID != "" && robotPartKey != "" && appAddress != "" {
			break
		}

		// If we haven't received all required credentials, try again a second later.
		if !bsl.listenForCredentialsHealth.Sleep(ctx, time.Second) {
			return ctx.Err()
		}
		continue
	}
	inputChan <- userInput{SSID: ssid, PSK: psk, PartID: robotPartKeyID, Secret: robotPartKey, AppAddr: appAddress}
	close(bsl.provisioningComplete)
	return nil
}

// listenForPairRequest ensures this device automatically accepts bluetooth pairing requests.
func listenForPairRequest(ctx context.Context, bsl *bluetoothServiceLinux) error {
	conn, err := dbus.SystemBus()
	if err != nil {
		return fmt.Errorf("failed to connect to system DBus: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	// Register bluez agent if not registered.
	if bsl.bluezAgentRegistered {
		bsl.logger.Debug("Bluez agent is already registered.")
		return nil
	}
	reply := conn.Export(nil, BluezAgentPath, BluezAgent)
	if reply != nil {
		return fmt.Errorf("failed to export Bluez agent: %w", reply)
	}
	obj := conn.Object(BluezDBusService, "/org/bluez")
	call := obj.Call("org.bluez.AgentManager1.RegisterAgent", 0, dbus.ObjectPath(BluezAgentPath), "NoInputNoOutput")
	if err := call.Err; err != nil {
		return fmt.Errorf("failed to register Bluez agent: %w", err)
	}
	call = obj.Call("org.bluez.AgentManager1.RequestDefaultAgent", 0, dbus.ObjectPath(BluezAgentPath))
	if err := call.Err; err != nil {
		return fmt.Errorf("failed to set default Bluez agent: %w", err)
	}
	bsl.logger.Debug("Bluez agent registered!")
	bsl.bluezAgentRegistered = true

	// Begin listening for property changes (i.e. bluetooth pairing requests)
	if bsl.listeningForPropertyChanges {
		bsl.logger.Debug("Already listening for property changes (bluetooth pairing requests) on the system D-bus.")
		return nil
	}
	matchRule := "type='signal',interface='org.freedesktop.DBus.Properties',member='PropertiesChanged'"
	err = conn.BusObject().Call("org.freedesktop.DBus.AddMatch", 0, matchRule).Err
	if err != nil {
		return fmt.Errorf("failed to add DBus match rule: %w", err)
	}
	bsl.listeningForPropertyChanges = true
	bsl.logger.Debug("Listening for property changes (bluetooth pairing requests) on system D-bus.")

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
		case <-bsl.provisioningComplete:
			return nil
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
			parts := strings.Split(devicePath, "/")
			if len(parts) < 4 {
				continue
			}

			// Extract last part and convert underscores to colons
			macPart := parts[len(parts)-1]
			deviceMAC := strings.ReplaceAll(macPart, "_", ":")
			if deviceMAC == "" {
				continue
			}

			// Trust device
			if slices.Contains(bsl.trustedDevices, devicePath) {
				bsl.logger.Debugf("Device: %s is already trusted", devicePath)
				return nil
			}
			obj := conn.Object(BluezDBusService, dbus.ObjectPath(devicePath))
			call := obj.Call("org.freedesktop.DBus.Properties.Set", 0,
				"org.bluez.Device1", "Trusted", dbus.MakeVariant(true))
			if call.Err != nil {
				return fmt.Errorf("failed to set Trusted property: %w", call.Err)
			}
			bsl.trustedDevices = append(bsl.trustedDevices, devicePath)
			bsl.logger.Debugf("Device: %s marked as trusted.", devicePath)

			return nil

		default:
			if !bsl.listenForPairRequestHealth.Sleep(ctx, time.Second) {
				return ctx.Err()
			}
		}
	}
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

const (
	BluezDBusService  = "org.bluez"
	BluezAgentPath    = "/custom/agent"
	BluezAgentManager = "org.bluez.AgentManager1"
	BluezAgent        = "org.bluez.Agent1"
)

// validateBlueZVersion retrieves the installed BlueZ version via D-Bus.
func validateBlueZVersion() error {
	var versionOutput bytes.Buffer
	var err error

	// Try to get version from bluetoothctl first, fallback to bluetoothd
	versionCmds := []string{"bluetoothctl --version", "bluetoothd --version"}
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
		return fmt.Errorf("BlueZ is not installed or not accessible")
	}

	// Extract only the numeric version
	versionStr := strings.TrimSpace(versionOutput.String())
	parts := strings.Fields(versionStr)

	// Ensure we have at least one part before accessing it
	if len(parts) == 0 {
		return fmt.Errorf("failed to parse BlueZ version: empty output")
	}

	versionNum := parts[len(parts)-1] // Get the last word, which should be the version number

	// Convert to float
	versionFloat, err := strconv.ParseFloat(versionNum, 64)
	if err != nil {
		return fmt.Errorf("failed to parse BlueZ version: %s", versionStr)
	}

	if versionFloat < 5.66 {
		return fmt.Errorf("BlueZ version is %.2f, but 5.66 or later is required", versionFloat)
	}
	return nil
}
