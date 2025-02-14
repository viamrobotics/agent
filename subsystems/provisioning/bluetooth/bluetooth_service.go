package ble

import (
	"context"
)

type bluetoothService interface {
	StartAdvertising(ctx context.Context) error
	StopAdvertising() error
	WriteWifiNetworks(awns *AvailableWiFiNetworks) error
	ReadSsid() (string, error)
	ReadPsk() (string, error)
	ReadRobotPartKeyID() (string, error)
	ReadRobotPartKey() (string, error)
}
