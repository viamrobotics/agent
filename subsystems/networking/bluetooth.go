package networking

import (
	"context"
)

const (
	ssidKey                  = "SSID"
	pskKey                   = "PSK"
	robotPartKeyIDKey        = "Robot Part Key ID"
	robotPartKeyKey          = "Robot Part Key"
	appAddressKey            = "App Address"
	availableWiFiNetworksKey = "Available WiFi Networks"
	isConnectedKey           = "Machine Network Connectivity State"
	isConfiguredKey          = "Machine Configured State"
)

// bluetoothService provides an interface for retrieving cloud config and/or WiFi credentials for a machine over bluetooth.
type bluetoothService interface {
	start(ctx context.Context, inputChat chan<- userInput) error
	stop() error
	healthy() bool
}
