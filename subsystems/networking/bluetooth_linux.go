package networking

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"tinygo.org/x/bluetooth"
)

// startProvisioningBluetooth should only be called by 'StartProvisioning' (to ensure opMutex is acquired).
func (n *Networking) startProvisioningBluetooth(ctx context.Context, inputChan chan<- userInput) error {
	if n.Config().DisableBTProvisioning || n.noBT {
		return nil
	}
	if n.btAdv != nil {
		return errors.New("invalid request, advertising already active")
	}

	// Create a bluetooth service comprised of the above configs.
	if err := n.initializeBluetoothService(n.Config().HotspotSSID, n.btChar.initCharacteristics()); err != nil {
		n.noBT = true
		return fmt.Errorf("failed to initialize bluetooth service: %w", err)
	}

	// Update bluetooth read-only characteristics
	if err := n.btChar.updateStatus(n.connState.getConfigured(), n.connState.getConnected() || n.connState.getOnline()); err != nil {
		n.logger.Warn("could not update BT status characteristic")
	}
	if err := n.btChar.updateNetworks(n.getVisibleNetworks()); err != nil {
		n.logger.Warn("could not update BT networks characteristic")
	}

	// Start the loop that monitors for BT writes.
	n.btChar.startBTLoop(ctx, inputChan)

	// Start advertising the bluetooth service.
	if err := n.btAdv.Start(); err != nil {
		return fmt.Errorf("failed to start advertising: %w", err)
	}

	n.logger.Info("Bluetooth provisioning started.")
	return nil
}

// stop stops advertising a bluetooth service which (when enabled) accepts WiFi and Viam cloud config credentials.
func (n *Networking) stopProvisioningBluetooth() error {
	if n.btAdv == nil {
		return nil
	}
	if err := n.btAdv.Stop(); err != nil {
		return fmt.Errorf("failed to stop BT advertising: %w", err)
	}
	n.btAdv = nil
	n.btChar.stopBTLoop()
	n.logger.Debug("Stopped advertising bluetooth service.")
	return nil
}

// initializeBluetoothService performs low-level system configuration to enable bluetooth advertisement.
func (n *Networking) initializeBluetoothService(deviceName string, characteristics []bluetooth.CharacteristicConfig) error {
	serviceUUID := bluetooth.NewUUID(uuid.NewSHA1(uuid.MustParse(uuidNamespace), []byte(serviceNameKey)))

	adapter := bluetooth.DefaultAdapter
	if err := adapter.Enable(); err != nil {
		return fmt.Errorf("failed to enable bluetooth adapter: %w", err)
	}
	if err := adapter.AddService(&bluetooth.Service{UUID: serviceUUID, Characteristics: characteristics}); err != nil {
		return fmt.Errorf("unable to add bluetooth service to default adapter: %w", err)
	}
	// if err := adapter.Enable(); err != nil {
	// 	return nil, fmt.Errorf("failed to enable bluetooth adapter: %w", err)
	// }
	adv := adapter.DefaultAdvertisement()
	opts := bluetooth.AdvertisementOptions{
		LocalName:    deviceName,
		ServiceUUIDs: []bluetooth.UUID{serviceUUID},
	}
	if err := adv.Configure(opts); err != nil {
		return fmt.Errorf("failed to configure default advertisement: %w", err)
	}
	n.btAdv = adv
	n.logger.Debugf("Bluetooth service UUID: %s.", serviceUUID.String())
	return nil
}
