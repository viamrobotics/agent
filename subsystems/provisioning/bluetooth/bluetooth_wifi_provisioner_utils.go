package ble

import (
	"context"
	"fmt"
	"time"

	"github.com/pkg/errors"
)

// emptyBluetoothCharacteristicError represents the error which is raised when we attempt to read from an empty BLE characteristic.
type emptyBluetoothCharacteristicError struct {
	missingValue string
}

func (e *emptyBluetoothCharacteristicError) Error() string {
	return fmt.Sprintf("no value has been written to BLE characteristic for %s", e.missingValue)
}

// retryCallbackOnExpectedError retries the provided callback to at one second intervals as long as an expected error is thrown.
func retryCallbackOnExpectedError(
	ctx context.Context, fn func() (string, error), expectedErr error, description string,
) (string, error) {
	for {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
			time.Sleep(time.Second)
		}
		v, err := fn()
		if err != nil {
			if errors.As(err, &expectedErr) {
				continue
			}
			return "", errors.WithMessagef(err, "%s", description)
		}
		return v, nil
	}
}
