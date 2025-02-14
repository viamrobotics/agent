package ble

import (
	"bytes"
	"fmt"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/godbus/dbus"
	"github.com/pkg/errors"
	"go.viam.com/rdk/logging"
)

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

// listenForPairing waits for an incoming BLE pairing request and automatically trusts the device.
func listenForPairing(logger logging.Logger) error {
	conn, err := dbus.SystemBus()
	if err != nil {
		return errors.WithMessage(err, "failed to connect to system DBus")
	}

	// Export agent methods
	reply := conn.Export(nil, BluezAgentPath, BluezAgent)
	if reply != nil {
		return errors.WithMessage(reply, "failed to export Bluez agent")
	}

	// Register the agent
	obj := conn.Object(BluezDBusService, "/org/bluez")
	call := obj.Call("org.bluez.AgentManager1.RegisterAgent", 0, dbus.ObjectPath(BluezAgentPath), "NoInputNoOutput")
	if err := call.Err; err != nil {
		return errors.WithMessage(err, "failed to register Bluez agent")
	}

	// Set as the default agent
	call = obj.Call("org.bluez.AgentManager1.RequestDefaultAgent", 0, dbus.ObjectPath(BluezAgentPath))
	if err := call.Err; err != nil {
		return errors.WithMessage(err, "failed to set default Bluez agent")
	}

	logger.Info("Bluez agent registered!")

	// Listen for properties changed events
	signalChan := make(chan *dbus.Signal, 10)
	conn.Signal(signalChan)

	// Add a match rule to listen for DBus property changes
	matchRule := "type='signal',interface='org.freedesktop.DBus.Properties',member='PropertiesChanged'"
	err = conn.BusObject().Call("org.freedesktop.DBus.AddMatch", 0, matchRule).Err
	if err != nil {
		return errors.WithMessage(err, "failed to add DBus match rule")
	}

	logger.Info("waiting for a BLE pairing request...")

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

		logger.Infof("device %s initiated pairing!", deviceMAC)

		// Mark device as trusted
		if err = trustDevice(logger, devicePath); err != nil {
			return errors.WithMessage(err, "failed to trust device")
		} else {
			logger.Info("device successfully trusted!")
		}
	}
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
