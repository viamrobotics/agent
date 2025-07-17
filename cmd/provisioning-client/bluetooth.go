package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	errw "github.com/pkg/errors"
	"tinygo.org/x/bluetooth"
)

// Copied from subsystems/networking/bluetooth_characteristics_linux.go.
const (
	// Random (v4) UUID for namespace.
	uuidNamespace = "74a942f4-0f45-43f4-88ca-f87021ae36ea"

	// These values will be combined into Sha1 (v5) UUIDs along with the above namespace.
	serviceNameKey           = "viam-provisioning"
	ssidKey                  = "ssid"
	pskKey                   = "psk"
	robotPartIDKey           = "id"
	robotPartSecretKey       = "secret"
	appAddressKey            = "app_address"
	availableWiFiNetworksKey = "networks"
	statusKey                = "status"
	manufacturerKey          = "manufacturer"
	modelKey                 = "model"
	fragmentKey              = "fragment_id"
	errorsKey                = "errors"
	cryptoKey                = "pub_key"
	exitProvisioningKey      = "exit_provisioning"
	agentVersionKey          = "agent_version"
	unlockPairingKey         = "unlock_pairing"
)

var pubKey *rsa.PublicKey

func btClient() error {
	adapter := bluetooth.DefaultAdapter

	if err := adapter.Enable(); err != nil {
		return err
	}

	if opts.BTScan {
		return BTScanOnly(adapter)
	}

	device, err := Connect()
	if err != nil {
		return errw.Wrap(err, "connecting")
	}

	chars, err := getCharicteristicsMap(device)
	if err != nil {
		return err
	}

	if opts.Status {
		if err := BTGetStatus(chars); err != nil {
			return err
		}
	}

	if opts.Info {
		if err := BTGetInfo(chars); err != nil {
			return err
		}
	}

	if opts.Networks {
		if err := BTGetNetworks(chars); err != nil {
			return err
		}
	}

	if opts.PartID != "" {
		if err := BTSetDeviceCreds(chars); err != nil {
			return err
		}
	}

	if opts.WifiSSID != "" {
		if err := BTSetWifiCreds(chars); err != nil {
			return err
		}
	}

	if opts.PartID != "" || opts.WifiSSID != "" {
		if err := BTExitProvisioning(chars); err != nil {
			return err
		}
	}

	if opts.UnlockPairing {
		if err := BTUnlockPairing(chars); err != nil {
			return err
		}
	}

	if opts.Exit {
		return ExitProvisioning(chars)
	}

	return nil
}

func ExitProvisioning(chars map[string]bluetooth.DeviceCharacteristic) error {
	fmt.Println("Sending exit command...")
	if err := initCrypto(chars); err != nil {
		return err
	}

	cryptExit, err := encrypt([]byte("1"))
	if err != nil {
		return err
	}

	_, err = chars[exitProvisioningKey].WriteWithoutResponse(cryptExit)
	if err != nil {
		return errw.Wrap(err, "writing app address")
	}
	return nil
}

func BTScanOnly(adapter *bluetooth.Adapter) error {
	fmt.Println("Scanning for bluetooth devices...")

	seen := make(map[string]bool)
	var err error
	go func() {
		err = adapter.Scan(
			func(adapter *bluetooth.Adapter, device bluetooth.ScanResult) {
				if device.LocalName() != "" {
					if seen[device.Address.String()] {
						return
					}
					seen[device.Address.String()] = true
					fmt.Printf("Found device: %s [%s]\n", device.LocalName(), device.Address.String())
				}
			},
		)
		if err != nil {
			fmt.Printf("error while scanning: %s", err.Error())
		}
	}()

	time.Sleep(time.Minute)
	err2 := adapter.StopScan()
	return errors.Join(err, err2)
}

func BTScan(adapter *bluetooth.Adapter) (bluetooth.Address, error) {
	fmt.Printf("Searching for device name that includes filter string: %s\n", opts.BTFilter)
	fmt.Println("Scanning...")

	ch := make(chan bluetooth.ScanResult, 1)

	go func() {
		err := adapter.Scan(
			func(adapter *bluetooth.Adapter, device bluetooth.ScanResult) {
				if strings.Contains(device.LocalName(), opts.BTFilter) {
					fmt.Printf("Found device: %s [%s]\n", device.LocalName(), device.Address.String())
					ch <- device
				}
			},
		)
		if err != nil {
			fmt.Printf("error while scanning: %s", err.Error())
		}
	}()

	var addr bluetooth.Address
	var good bool

	select {
	case result := <-ch:
		good = true
		addr = result.Address
	case <-time.After(time.Second * 30):
	}
	err := adapter.StopScan()
	if !good {
		return addr, errors.Join(err, fmt.Errorf("failed to find device matching filter: %s", opts.BTFilter))
	}

	return addr, err
}

func BTGetInfo(chars map[string]bluetooth.DeviceCharacteristic) error {
	buf := make([]byte, 512)
	var manufacturer, model, fragment, agentVersion string
	var errList []string
	for _, c := range []string{manufacturerKey, modelKey, fragmentKey, agentVersionKey, errorsKey} {
		size, err := chars[c].Read(buf)
		if err != nil {
			return errw.Wrap(err, "reading status")
		}
		switch c {
		case manufacturerKey:
			manufacturer = string(buf[:size])
		case modelKey:
			model = string(buf[:size])
		case fragmentKey:
			fragment = string(buf[:size])
		case agentVersionKey:
			agentVersion = string(buf[:size])
		case errorsKey:
			for _, devErr := range bytes.Split(buf[:size], []byte{0x0}) {
				errList = append(errList, string(devErr))
			}
		}
	}
	fmt.Printf("Manufacturer: %s, Model: %s, Fragment: %s, Agent Version: %s, Errors: %v\n",
		manufacturer, model, fragment, agentVersion, errList,
	)
	return nil
}

func BTGetStatus(chars map[string]bluetooth.DeviceCharacteristic) error {
	buf := make([]byte, 512)
	size, err := chars[statusKey].Read(buf)
	if err != nil {
		return errw.Wrap(err, "reading status")
	}

	if size != 1 {
		return fmt.Errorf("status characteristic is the wrong size: %d", size)
	}

	// status is a bitpacked byte, bit 0=isConfigured, bit 1=isConnected is
	var isConfigured, isConnected bool
	switch buf[0] {
	case 0:
	case 1:
		isConfigured = true
	case 2:
		isConnected = true
	case 3:
		isConfigured = true
		isConnected = true
	default:
		fmt.Printf("Unknown status raw value: %d\n", buf[0])
	}

	fmt.Printf("Viam Device Status: Configured: %t, Connected: %t\n", isConfigured, isConnected)
	return nil
}

func BTGetNetworks(chars map[string]bluetooth.DeviceCharacteristic) error {
	buf := make([]byte, 512)
	size, err := chars[availableWiFiNetworksKey].Read(buf)
	if err != nil {
		return errw.Wrap(err, "reading network list")
	}

	// networks are split on null bytes, and the first byte of each is a single bit for security, and 7 bits for signal strength (0-100)
	nets := bytes.Split(buf[:size], []byte{0x0})

	fmt.Println("Networks:")
	for _, net := range nets {
		if len(net) < 2 {
			// last network gets terminated with a null, so we get one empty []byte at the end
			continue
		}

		meta := net[0]
		isSecure := meta > 127
		signal := meta &^ byte(1<<7)
		ssid := net[1:]
		fmt.Printf("SSID: %s, Signal: %d, IsSecure: %t\n", ssid, signal, isSecure)
	}
	return nil
}

func BTSetDeviceCreds(chars map[string]bluetooth.DeviceCharacteristic) error {
	fmt.Println("Writing device credentials...")
	if err := initCrypto(chars); err != nil {
		return err
	}

	cryptPartID, err := encrypt([]byte(opts.PartID))
	if err != nil {
		return err
	}

	cryptSecret, err := encrypt([]byte(opts.Secret))
	if err != nil {
		return err
	}

	cryptAppAddr, err := encrypt([]byte(opts.AppAddr))
	if err != nil {
		return err
	}

	_, err = chars[robotPartIDKey].WriteWithoutResponse(cryptPartID)
	if err != nil {
		return errw.Wrap(err, "writing part id")
	}

	_, err = chars[robotPartSecretKey].WriteWithoutResponse(cryptSecret)
	if err != nil {
		return errw.Wrap(err, "writing secret")
	}

	_, err = chars[appAddressKey].WriteWithoutResponse(cryptAppAddr)
	if err != nil {
		return errw.Wrap(err, "writing app address")
	}

	return nil
}

func BTSetWifiCreds(chars map[string]bluetooth.DeviceCharacteristic) error {
	fmt.Println("Writing wifi credentials...")
	if err := initCrypto(chars); err != nil {
		return err
	}

	cryptSSID, err := encrypt([]byte(opts.WifiSSID))
	if err != nil {
		return err
	}

	cryptPSK, err := encrypt([]byte(opts.WifiPSK))
	if err != nil {
		return err
	}

	_, err = chars[ssidKey].WriteWithoutResponse(cryptSSID)
	if err != nil {
		return errw.Wrap(err, "writing ssid")
	}

	_, err = chars[pskKey].WriteWithoutResponse(cryptPSK)
	if err != nil {
		return errw.Wrap(err, "writing psk")
	}
	return nil
}

func BTUnlockPairing(chars map[string]bluetooth.DeviceCharacteristic) error {
	fmt.Println("writing unlock pairing request...")
	if err := initCrypto(chars); err != nil {
		return err
	}

	cryptAddr, err := encrypt([]byte("1"))
	if err != nil {
		return err
	}

	_, err = chars[unlockPairingKey].WriteWithoutResponse(cryptAddr)
	if err != nil {
		return errw.Wrap(err, "writing unlock pairing request")
	}

	return nil
}

func BTExitProvisioning(chars map[string]bluetooth.DeviceCharacteristic) error {
	fmt.Println("Sending exit command...")
	if err := initCrypto(chars); err != nil {
		return err
	}

	cryptExit, err := encrypt([]byte("1"))
	if err != nil {
		return err
	}

	_, err = chars[exitProvisioningKey].WriteWithoutResponse(cryptExit)
	if err != nil {
		return errw.Wrap(err, "writing exit command")
	}
	return nil
}

func getUUID(key string) bluetooth.UUID {
	return bluetooth.NewUUID(uuid.NewSHA1(uuid.MustParse(uuidNamespace), []byte(key)))
}

func Connect() (*bluetooth.Device, error) {
	adapter := bluetooth.DefaultAdapter
	addr, err := BTScan(adapter)
	if err != nil {
		return nil, err
	}
	fmt.Println("Connecting...")
	device, err := adapter.Connect(addr, bluetooth.ConnectionParams{})
	if err != nil {
		return nil, errw.Wrap(err, "connecting device")
	}
	return &device, nil
}

func Disconnect(device *bluetooth.Device) {
	fmt.Println("Disconnecting...")
	err := device.Disconnect()
	if err != nil {
		println(err)
	}
}

func getCharicteristicsMap(device *bluetooth.Device) (map[string]bluetooth.DeviceCharacteristic, error) {
	charMap := make(map[string]bluetooth.DeviceCharacteristic)

	fmt.Printf("Discovering characteristics for service UUID: %s\n", getUUID(serviceNameKey))
	srvcs, err := device.DiscoverServices([]bluetooth.UUID{getUUID(serviceNameKey)})
	if err != nil {
		return charMap, errw.Wrap(err, "discovering service")
	}
	chars, err := srvcs[0].DiscoverCharacteristics(nil)
	if err != nil {
		return charMap, errw.Wrap(err, "discovering characteristics")
	}

	for _, char := range chars {
		var key string
		switch char.UUID() {
		case getUUID(statusKey):
			key = statusKey
			charMap[statusKey] = char
		case getUUID(availableWiFiNetworksKey):
			key = availableWiFiNetworksKey
			charMap[availableWiFiNetworksKey] = char
		case getUUID(errorsKey):
			key = errorsKey
			charMap[errorsKey] = char
		case getUUID(ssidKey):
			key = ssidKey
			charMap[ssidKey] = char
		case getUUID(pskKey):
			key = pskKey
			charMap[pskKey] = char
		case getUUID(appAddressKey):
			key = appAddressKey
			charMap[appAddressKey] = char
		case getUUID(robotPartIDKey):
			key = robotPartIDKey
			charMap[robotPartIDKey] = char
		case getUUID(robotPartSecretKey):
			key = robotPartSecretKey
			charMap[robotPartSecretKey] = char
		case getUUID(cryptoKey):
			key = cryptoKey
			charMap[cryptoKey] = char
		case getUUID(manufacturerKey):
			key = manufacturerKey
			charMap[manufacturerKey] = char
		case getUUID(modelKey):
			key = modelKey
			charMap[modelKey] = char
		case getUUID(fragmentKey):
			key = fragmentKey
			charMap[fragmentKey] = char
		case getUUID(agentVersionKey):
			key = agentVersionKey
			charMap[agentVersionKey] = char
		case getUUID(exitProvisioningKey):
			key = exitProvisioningKey
			charMap[exitProvisioningKey] = char
		case getUUID(unlockPairingKey):
			key = unlockPairingKey
			charMap[unlockPairingKey] = char

		default:
			fmt.Printf("Unknown characteristic discovered with UUID: %s", char.String())
		}
		fmt.Printf("Found: %s (%s)\n", char.UUID().String(), key)
	}

	return charMap, nil
}

func encrypt(plaintext []byte) ([]byte, error) {
	// append the PSK for security
	plaintext = append([]byte(opts.PSK+":"), plaintext...)
	// using sha256 for the hash, OAEP allows for messages up to 190 bytes (minus the PSK size+1)
	crypttext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plaintext, nil)
	return crypttext, err
}

func initCrypto(chars map[string]bluetooth.DeviceCharacteristic) error {
	if pubKey != nil {
		return nil
	}

	buf := make([]byte, 512)
	size, err := chars[cryptoKey].Read(buf)
	if err != nil {
		return errw.Wrap(err, "reading crypto psk")
	}

	ifc, err := x509.ParsePKIXPublicKey(buf[:size])
	if err != nil {
		return err
	}
	key, ok := ifc.(*rsa.PublicKey)
	if !ok {
		return errw.New("cannot cast to public key")
	}
	pubKey = key
	return nil
}
