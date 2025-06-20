package networking

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
	"tinygo.org/x/bluetooth"
)

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
)

var (
	characteristicsWriteOnly = []string{ssidKey, pskKey, robotPartIDKey, robotPartSecretKey, appAddressKey}
	characteristicsReadOnly  = []string{cryptoKey, statusKey, manufacturerKey, modelKey, fragmentKey, availableWiFiNetworksKey, errorsKey}
)

type btCharacteristics struct {
	logger logging.Logger

	// Used to store user input values written to this bluetooth service.
	mu        sync.RWMutex
	writables map[string]*bluetooth.Characteristic

	userInputData *userInputData

	privKey *rsa.PrivateKey
}

func newBTCharacteristics(logger logging.Logger, userInputData *userInputData) *btCharacteristics {
	return &btCharacteristics{
		logger:        logger,
		writables:     map[string]*bluetooth.Characteristic{},
		userInputData: userInputData,
	}
}

func (b *btCharacteristics) initCharacteristics() []bluetooth.CharacteristicConfig {
	b.mu.Lock()
	defer b.mu.Unlock()
	var charList []bluetooth.CharacteristicConfig
	for _, char := range characteristicsWriteOnly {
		charList = append(charList, b.initWriteOnlyCharacteristic(char))
	}

	for _, char := range characteristicsReadOnly {
		cfg := b.initReadOnlyCharacteristic(char)
		charList = append(charList, cfg)
		b.writables[char] = cfg.Handle
	}

	return charList
}

func (b *btCharacteristics) initCrypto() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.privKey == nil {
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}

		b.privKey = privKey
	}

	// write the public crypto key
	pubKey, err := x509.MarshalPKIXPublicKey(&b.privKey.PublicKey)
	if err != nil {
		return err
	}
	_, err = b.writables[cryptoKey].Write(pubKey)
	return err
}

func (b *btCharacteristics) initDevInfo(cfg utils.NetworkConfiguration) error {
	return errors.Join(
		b.writeCharacteristic(manufacturerKey, []byte(cfg.Manufacturer)),
		b.writeCharacteristic(modelKey, []byte(cfg.Model)),
		b.writeCharacteristic(fragmentKey, []byte(cfg.FragmentID)),
	)
}

// initWriteOnlyCharacteristic returns a bluetooth characteristic config.
func (b *btCharacteristics) initWriteOnlyCharacteristic(cName string) bluetooth.CharacteristicConfig {
	// Generate predictable (v5) UUID from common namespace+cName
	cUUID := bluetooth.NewUUID(uuid.NewSHA1(uuid.MustParse(uuidNamespace), []byte(cName)))

	b.logger.Debugf("%s can be written to BT characteristic: %s", cName, cUUID.String())
	return bluetooth.CharacteristicConfig{
		UUID:  cUUID,
		Flags: bluetooth.CharacteristicWritePermission | bluetooth.CharacteristicWriteWithoutResponsePermission,

		// WriteEvent is triggered by BT, and we store it in the valuesByName map
		WriteEvent: func(client bluetooth.Connection, offset int, value []byte) {
			plaintext, err := b.decrypt(value)
			if err != nil {
				b.logger.Error(fmt.Errorf("could not decrypt incoming value for %s: %w", cName, err))
			}
			b.recordInput(cName, string(plaintext))
			b.logger.Debugf("Received %s: %s (cipher/plain sizes: %d/%d)", cName, plaintext, len(value), len(plaintext))
		},
	}
}

// initReadOnlyCharacteristic returns a bluetooth characteristic config.
func (b *btCharacteristics) initReadOnlyCharacteristic(cName string) bluetooth.CharacteristicConfig {
	// Generate predictable (v5) UUID from common namespace+cName
	cUUID := bluetooth.NewUUID(uuid.NewSHA1(uuid.MustParse(uuidNamespace), []byte(cName)))

	b.logger.Debugf("%s can be read from BT characteristic: %s", cName, cUUID.String())
	return bluetooth.CharacteristicConfig{
		Handle: &bluetooth.Characteristic{},
		UUID:   cUUID,
		Flags:  bluetooth.CharacteristicReadPermission | bluetooth.CharacteristicNotifyPermission,
	}
}

func (b *btCharacteristics) writeCharacteristic(cName string, value []byte) error {
	b.mu.RLock()
	defer b.mu.RUnlock()
	char, ok := b.writables[cName]
	if !ok {
		return fmt.Errorf("no writable characteristic named %s", cName)
	}
	_, err := char.Write(value)
	return err
}

func (b *btCharacteristics) updateNetworks(networks []NetworkInfo) error {
	// Writes are capped at a maximum of 512 bytes (bluetooth-low-energy protocol defines this behavior).
	var msg []byte
	for _, network := range networks {
		remainingBytes := 512 - len(msg)
		// Can convert network
		if network.Signal > 100 {
			network.Signal = 100
		}
		if network.Signal < 0 {
			network.Signal = 0
		}
		meta := uint8(network.Signal)
		if network.Security != "" && network.Security != "-" {
			meta |= (1 << 7)
		}
		compressedNetwork := []byte{meta}
		compressedNetwork = append(compressedNetwork, []byte(network.SSID)...)
		compressedNetwork = append(compressedNetwork, 0x0)

		// Break from loop if we don't have the space
		if len(compressedNetwork) > remainingBytes {
			break
		}
		msg = append(msg, compressedNetwork...)
	}
	return b.writeCharacteristic(availableWiFiNetworksKey, msg)
}

func (b *btCharacteristics) updateStatus(isConfigured, isConnected bool) error {
	var status uint8
	if isConfigured {
		status = 0b00000001
	}
	if isConnected {
		status |= 0b00000010
	}
	return b.writeCharacteristic(statusKey, []byte{status})
}

func (b *btCharacteristics) updateErrors(errList []string) error {
	var msg []byte
	for _, e := range errList {
		remainingBytes := 512 - len(msg)
		newErr := []byte(e)
		newErr = append(newErr, 0x0)

		// Break from loop if we don't have the space
		if len(newErr) > remainingBytes {
			break
		}
		msg = append(msg, newErr...)
	}
	return b.writeCharacteristic(errorsKey, msg)
}

func (b *btCharacteristics) decrypt(ciphertext []byte) ([]byte, error) {
	if b.privKey == nil {
		return nil, errors.New("private key not initialized")
	}
	// using sha256 for the hash, OAEP allows for messages up to 190 bytes
	return rsa.DecryptOAEP(sha256.New(), nil, b.privKey, ciphertext, nil)
}

func (b *btCharacteristics) recordInput(cName, value string) {
	b.userInputData.mu.Lock()
	defer b.userInputData.mu.Unlock()

	b.userInputData.connState.setLastInteraction()

	switch cName {
	case ssidKey:
		b.userInputData.input.SSID = value
	case pskKey:
		b.userInputData.input.PSK = value
	case robotPartIDKey:
		b.userInputData.input.PartID = value
	case robotPartSecretKey:
		b.userInputData.input.Secret = value
	case appAddressKey:
		b.userInputData.input.AppAddr = value
	}

	b.userInputData.sendInput(false)
}
