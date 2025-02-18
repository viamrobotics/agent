package ble

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus"
	"github.com/pkg/errors"
	"go.viam.com/rdk/logging"
)

// emptyBluetoothCharacteristicError represents the error which is raised when we attempt to read from an empty BLE characteristic.
type emptyBluetoothCharacteristicError struct {
	missingValue string
}

func (e *emptyBluetoothCharacteristicError) Error() string {
	return fmt.Sprintf("no value has been written to BLE characteristic for %s", e.missingValue)
}

func newEmptyBluetoothCharacteristicError(missingValue string) error {
	return &emptyBluetoothCharacteristicError{
		missingValue: missingValue,
	}
}

// waitForBLE is used to check for the existence of a new value in a BLE characteristic.
func waitForBLEValue(
	ctx context.Context, fn func() (string, error), description string,
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
			var errBLECharNoValue *emptyBluetoothCharacteristicError
			if errors.As(err, &errBLECharNoValue) {
				continue
			}
			return "", errors.WithMessagef(err, "failed to read %s", description)
		}
		return v, nil
	}
}

const (
	BluezDBusService  = "org.bluez"
	BluezAgentPath    = "/custom/agent"
	BluezAgentManager = "org.bluez.AgentManager1"
	BluezAgent        = "org.bluez.Agent1"
)

// checkOS verifies the system is running a Linux distribution.
func checkOS() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("this program requires Linux, detected: %s", runtime.GOOS)
	}
	return nil
}

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

// validateSystem checks OS and BlueZ installation/version.
func validateSystem(logger logging.Logger) error {
	// 1. Validate OS
	if err := checkOS(); err != nil {
		return err
	}
	logger.Info("✅ Running on a Linux system.")

	// 2. Check BlueZ version
	blueZVersion, err := getBlueZVersion()
	if err != nil {
		return err
	}
	logger.Infof("✅ BlueZ detected, version: %.2f", blueZVersion)

	// 3. Validate BlueZ version is 5.66 or higher
	if blueZVersion < 5.66 {
		return fmt.Errorf("❌ BlueZ version is %.2f, but 5.66 or later is required", blueZVersion)
	}

	logger.Info("✅ BlueZ version meets the requirement (5.66 or later).")
	return nil
}

// trustDevice sets the device as trusted and connects to it.
func trustDevice(logger logging.Logger, devicePath string) error {
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
	logger.Info("device marked as trusted.")

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
