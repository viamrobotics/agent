package provisioning

import (
	"context"

	"github.com/viamrobotics/agent/subsystems/provisioning/bluetooth"
	ble "github.com/viamrobotics/agent/subsystems/provisioning/bluetooth/bluetoothlowenergy"
	"go.viam.com/rdk/logging"
)

func bluetoothWiFiProvisioningExample(ctx context.Context, logger logging.Logger) {
	bwp, err := bluetooth.NewBluetoothWiFiProvisioner(ctx, logger, "Max's Bluetooth Peripheral")
	if err != nil {
		logger.Fatal(err)
	}

	// Pass available WiFi networks from Agent's network manager to the bluetooth peripheral so it
	// can send those "options" over bluetooth. Assuming a mobile app is connected via bluetooth,
	// it can advertise the available WiFi networks to the user in a dropdown selection.
	wifiNetworks := &ble.AvailableWiFiNetworks{
		Networks: []*struct {
			Ssid        string  `json:"ssid"`
			Strength    float64 `json:"strength"`
			RequiresPsk bool    `json:"requires_psk"`
		}{
			{
				Ssid:        "HomeWiFi",
				Strength:    0.85,
				RequiresPsk: true,
			},
			{
				Ssid:        "GuestWiFi",
				Strength:    0.65,
				RequiresPsk: false,
			},
		},
	}
	if err := bwp.RefreshAvailableWiFi(ctx, wifiNetworks); err != nil {
		logger.Fatal(err)
	}

	// RefreshAvailableWiFi is separate from Start because we will repeatedly call to refresh
	// the advertised available networks, but we will only call start once at the beginning.
	if err := bwp.Start(ctx); err != nil {
		logger.Fatal(err)
	}

	wifiCredentials, err := bwp.WaitForWiFiCredentials(ctx) // This is blocking.
	if err != nil {
		logger.Fatal(err)
	}
	logger.Infof("user provided SSID: %s and Psk: %s, will attempt to connect with those WiFi credentials...",
		wifiCredentials.Ssid, wifiCredentials.Psk)

	cloudCredentials, err := bwp.WaitForCloudCredentials(ctx) // This is blocking.
	if err != nil {
		logger.Fatal(err)
	}
	logger.Infof("user provided Robot Part Key ID: %s and Robot Part Key: %s, will attempt to connect with those cloud config credentials...",
		cloudCredentials.RobotPartKeyID, cloudCredentials.RobotPartKey)

	// Stop once we've gotten all required credentials, at which point the existing Agent provisioning loop can proceed.
	if err := bwp.Stop(ctx); err != nil {
		logger.Fatal(err)
	}
}
