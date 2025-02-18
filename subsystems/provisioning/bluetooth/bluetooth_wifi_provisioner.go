// Package ble contains an interface for using bluetooth-low-energy to retrieve WiFi and robot part credentials for an unprovisioned Agent.
package ble

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"errors"

	"github.com/godbus/dbus"
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
	bwp.mu.Lock()
	defer bwp.mu.Unlock()

	if bwp.adv == nil {
		return errors.New("advertisement is nil")
	}
	if bwp.advActive {
		return errors.New("invalid request, advertising already active")
	}
	if err := bwp.adv.Start(); err != nil {
		return errw.WithMessage(err, "failed to start advertising")
	}
	bwp.advActive = true
	bwp.logger.Info("started advertising a BLE connection...")
	return nil
}

func (bwp *BluetoothWiFiProvisioner) stopAdvertisingBLE() error {
	bwp.mu.Lock()
	defer bwp.mu.Unlock()

	if bwp.adv == nil {
		return errors.New("advertisement is nil")
	}
	if !bwp.advActive {
		return errors.New("invalid request, advertising already inactive")
	}
	if err := bwp.adv.Stop(); err != nil {
		return errw.WithMessage(err, "failed to stop advertising")
	}
	bwp.advActive = false
	bwp.logger.Info("stopped advertising a BLE connection")
	return nil
}

func (bwp *BluetoothWiFiProvisioner) enableAutoAcceptPairRequest() {
	var err error
	utils.ManagedGo(func() {
		conn, err := dbus.SystemBus()
		if err != nil {
			err = errw.WithMessage(err, "failed to connect to system DBus")
			return
		}

		// Export agent methods
		reply := conn.Export(nil, BluezAgentPath, BluezAgent)
		if reply != nil {
			err = errw.WithMessage(reply, "failed to export Bluez agent")
			return
		}

		// Register the agent
		obj := conn.Object(BluezDBusService, "/org/bluez")
		call := obj.Call("org.bluez.AgentManager1.RegisterAgent", 0, dbus.ObjectPath(BluezAgentPath), "NoInputNoOutput")
		if err := call.Err; err != nil {
			err = errw.WithMessage(err, "failed to register Bluez agent")
			return
		}

		// Set as the default agent
		call = obj.Call("org.bluez.AgentManager1.RequestDefaultAgent", 0, dbus.ObjectPath(BluezAgentPath))
		if err := call.Err; err != nil {
			err = errw.WithMessage(err, "failed to set default Bluez agent")
			return
		}

		bwp.logger.Info("Bluez agent registered!")

		// Listen for properties changed events
		signalChan := make(chan *dbus.Signal, 10)
		conn.Signal(signalChan)

		// Add a match rule to listen for DBus property changes
		matchRule := "type='signal',interface='org.freedesktop.DBus.Properties',member='PropertiesChanged'"
		err = conn.BusObject().Call("org.freedesktop.DBus.AddMatch", 0, matchRule).Err
		if err != nil {
			err = errw.WithMessage(err, "failed to add DBus match rule")
			return
		}

		bwp.logger.Info("waiting for a BLE pairing request...")

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

			bwp.logger.Infof("device %s initiated pairing!", deviceMAC)

			// Mark device as trusted
			if err = trustDevice(bwp.logger, devicePath); err != nil {
				err = errw.WithMessage(err, "failed to trust device")
				return
			} else {
				bwp.logger.Info("device successfully trusted!")
			}
		}
	}, nil)
	if err != nil {
		bwp.logger.Errorw(
			"failed to listen for pairing request (will have to manually accept pairing request on device)",
			"err", err)
	}
}

func (bwp *BluetoothWiFiProvisioner) writeAvailableNetworks(ctx context.Context, networks *AvailableWiFiNetworks) error {
	bwp.availableWiFiNetworksChannelWriteOnly <- networks
	return nil
}

func (bwp *BluetoothWiFiProvisioner) readSsid() (string, error) {
	if bwp.characteristicSsid == nil {
		return "", errors.New("characteristic ssid is nil")
	}

	bwp.characteristicSsid.mu.Lock()
	defer bwp.characteristicSsid.mu.Unlock()

	if !bwp.characteristicSsid.active {
		return "", errors.New("characteristic ssid is inactive")
	}
	if bwp.characteristicSsid.currentValue == nil {
		return "", newEmptyBluetoothCharacteristicError("ssid")
	}
	return *bwp.characteristicSsid.currentValue, nil
}

func (bwp *BluetoothWiFiProvisioner) readPsk() (string, error) {
	if bwp.characteristicPsk == nil {
		return "", errors.New("characteristic psk is nil")
	}

	bwp.characteristicPsk.mu.Lock()
	defer bwp.characteristicPsk.mu.Unlock()

	if !bwp.characteristicPsk.active {
		return "", errors.New("characteristic psk is inactive")
	}
	if bwp.characteristicPsk.currentValue == nil {
		return "", newEmptyBluetoothCharacteristicError("psk")
	}
	return *bwp.characteristicPsk.currentValue, nil
}

func (bwp *BluetoothWiFiProvisioner) readRobotPartKeyID() (string, error) {
	if bwp.characteristicRobotPartKeyID == nil {
		return "", errors.New("characteristic robot part key ID is nil")
	}

	bwp.characteristicRobotPartKeyID.mu.Lock()
	defer bwp.characteristicRobotPartKeyID.mu.Unlock()

	if !bwp.characteristicRobotPartKeyID.active {
		return "", errors.New("characteristic robot part key ID is inactive")
	}
	if bwp.characteristicRobotPartKeyID.currentValue == nil {
		return "", newEmptyBluetoothCharacteristicError("robot part key ID")
	}
	return *bwp.characteristicRobotPartKeyID.currentValue, nil
}

func (bwp *BluetoothWiFiProvisioner) readRobotPartKey() (string, error) {
	if bwp.characteristicRobotPartKey == nil {
		return "", errors.New("characteristic robot part key is nil")
	}

	bwp.characteristicRobotPartKey.mu.Lock()
	defer bwp.characteristicRobotPartKey.mu.Unlock()

	if !bwp.characteristicRobotPartKey.active {
		return "", errors.New("characteristic robot part key is inactive")
	}
	if bwp.characteristicRobotPartKey.currentValue == nil {
		return "", newEmptyBluetoothCharacteristicError("robot part key")
	}
	return *bwp.characteristicRobotPartKey.currentValue, nil
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

		availableWiFiNetworksChannelWriteOnly: availableWiFiNetworksChannel,

		characteristicSsid:           charSsid,
		characteristicPsk:            charPsk,
		characteristicRobotPartKeyID: charRobotPartKeyID,
		characteristicRobotPartKey:   charRobotPartKey,
	}, nil
}
