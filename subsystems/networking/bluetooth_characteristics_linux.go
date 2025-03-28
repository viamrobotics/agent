package networking

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
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
	errorsKey                = "errors"
	cryptoKey                = "pub_key"
)

var (
	characteristicsWO = []string{ssidKey, pskKey, robotPartIDKey, robotPartSecretKey, appAddressKey}
	characteristicsRO = []string{cryptoKey, statusKey, availableWiFiNetworksKey, errorsKey}
)

type btCharacteristics struct {
	logger logging.Logger

	// Used to store user input values written to this bluetooth service.
	mu        sync.RWMutex
	values    map[string]string
	writables map[string]*bluetooth.Characteristic

	workers sync.WaitGroup
	cancel  context.CancelFunc
	health  *health

	privKey *rsa.PrivateKey
}

func newBTCharacteristics(logger logging.Logger) *btCharacteristics {
	return &btCharacteristics{
		logger: logger,
		values: map[string]string{
			ssidKey:            "",
			pskKey:             "",
			robotPartIDKey:     "",
			robotPartSecretKey: "",
			appAddressKey:      "",
		},
		writables: map[string]*bluetooth.Characteristic{},
		health:    &health{},
	}
}

func (b *btCharacteristics) initCharacteristics() []bluetooth.CharacteristicConfig {
	b.mu.Lock()
	defer b.mu.Unlock()
	var charList []bluetooth.CharacteristicConfig
	for _, char := range characteristicsWO {
		charList = append(charList, b.initWOCharacteristic(char))
	}

	for _, char := range characteristicsRO {
		cfg := b.initROCharacteristic(char)
		charList = append(charList, cfg)
		b.writables[char] = cfg.Handle
	}

	return charList
}

func (b *btCharacteristics) initCrypto() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	b.privKey = privKey

	// write the public crypto key
	pubKey, err := x509.MarshalPKIXPublicKey(&b.privKey.PublicKey)
	if err != nil {
		return err
	}
	_, err = b.writables[cryptoKey].Write(pubKey)
	return err
}

// initWOCharacteristic returns a bluetooth characteristic config.
func (b *btCharacteristics) initWOCharacteristic(cName string) bluetooth.CharacteristicConfig {
	// Generate predictable (v5) UUID from common namespace+cName
	cUUID := bluetooth.NewUUID(uuid.NewSHA1(uuid.MustParse(uuidNamespace), []byte(cName)))

	b.logger.Debugf("%s can be written to BT characteristic: %s", cName, cUUID.String())
	return bluetooth.CharacteristicConfig{
		UUID:  cUUID,
		Flags: bluetooth.CharacteristicWritePermission | bluetooth.CharacteristicWriteWithoutResponsePermission,

		// WriteEvent is triggered by BT, and we store it in the valuesByName map
		WriteEvent: func(client bluetooth.Connection, offset int, value []byte) {
			b.mu.Lock()
			defer b.mu.Unlock()

			plaintext, err := b.decrypt(value)
			if err != nil {
				b.logger.Errorf("could not decrypt incoming value for %s: %w", cName, err)
			}

			b.values[cName] = string(plaintext)
			b.logger.Debugf("Received %s: %s (cipher/plain sizes: %d/%d)", cName, plaintext, len(value), len(plaintext))
		},
	}
}

// initROCharacteristic returns a bluetooth characteristic config.
func (b *btCharacteristics) initROCharacteristic(cName string) bluetooth.CharacteristicConfig {
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

func (b *btCharacteristics) readCharacteristic(cName string) string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	value, ok := b.values[cName]
	if !ok {
		b.logger.Warnf("no readable characteristic named %s", cName)
		return ""
	}
	return value
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

// startBTLoop returns credentials, the minimum required information to provision a robot and/or its WiFi.
func (b *btCharacteristics) startBTLoop(ctx context.Context, inputChan chan<- userInput) {
	input := &userInput{}
	ctx, b.cancel = context.WithCancel(ctx)
	b.health.MarkGood()
	b.workers.Add(1)
	go func() {
		defer b.workers.Done()
		for {
			// If new values are provided, persist them to in-memory storage.
			input.SSID = b.readCharacteristic(ssidKey)
			input.PSK = b.readCharacteristic(pskKey)

			input.PartID = b.readCharacteristic(robotPartIDKey)
			input.Secret = b.readCharacteristic(robotPartSecretKey)
			input.AppAddr = b.readCharacteristic(appAddressKey)

			// If we've received a "set" of required credentials, pass them through inputChan.
			hasWifiInput := input.SSID != "" && input.PSK != ""
			hasCredInput := input.AppAddr != "" && input.PartID != "" && input.Secret != ""

			if hasWifiInput || hasCredInput {
				inputChan <- *input
				if hasWifiInput {
					// reset for next round
					input.SSID = ""
					input.PSK = ""
				}
				if hasCredInput {
					input.AppAddr = ""
					input.PartID = ""
					input.Secret = ""
				}
			}

			// If we haven't received all required credentials, sleep and try again.
			if !b.health.Sleep(ctx, time.Second*5) {
				return
			}
		}
	}()
}

func (b *btCharacteristics) stopBTLoop() {
	if b.cancel != nil {
		b.cancel()
	}
	b.workers.Wait()
}

func (b *btCharacteristics) decrypt(ciphertext []byte) ([]byte, error) {
	if b.privKey == nil {
		return nil, errors.New("private key not initialized")
	}
	// using sha256 for the hash, OAEP allows for messages up to 190 bytes
	return rsa.DecryptOAEP(sha256.New(), nil, b.privKey, ciphertext, nil)
}
