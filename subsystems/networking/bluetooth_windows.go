package networking

import (
	"context"

	"go.viam.com/rdk/logging"
)

// bluetoothServiceWindows is a dummy version for now.
type bluetoothServiceWindows struct{}

func newBluetoothService(
	_ logging.Logger,
	_ string,
	_ func() []NetworkInfo,
	_ func() bool,
	_ func() bool,
) (bluetoothService, error) {
	return &bluetoothServiceWindows{}, nil
}

func (bsw *bluetoothServiceWindows) start(_ context.Context, _ chan<- userInput) error {
	return nil
}

func (bsw *bluetoothServiceWindows) stop() error {
	return nil
}

func (bsw *bluetoothServiceWindows) healthy() bool {
	return true
}
