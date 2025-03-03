package networking

import (
	"context"
	"errors"
	"testing"

	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
	"go.viam.com/test"
)

func TestProvisioningOverBluetooth(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewTestLogger(t)
	n, bsm := newNetworkingWithBluetoothServiceMock(t, ctx, logger)
	test.That(t, n, test.ShouldNotBeNil)
	inputChan := make(chan userInput, 1)
	defer close(inputChan)

	/*
		There is no variability in inputs passed to either StartProvisioning or
		StopProvisioning, so provisioning state validation should suffice for
		unit testing.
	*/

	/*
		Case 1: Successfully start, asynch wait for credentials, and stop bluetooth provisioning.
	*/
	bsm.shouldFailToStart = false
	bsm.shouldFailToWaitForCredentials = false
	bsm.shouldFailToStop = false

	// Validate networking state from before starting provisioning flow.
	test.That(t, n.connState.provisioningMode, test.ShouldBeFalse)
	test.That(t, n.connState.getProvisioningBluetooth(), test.ShouldBeFalse)

	err := n.StartProvisioning(ctx, inputChan)
	test.That(t, err, test.ShouldBeNil)

	// Validate networking state from after starting provisioning flow.
	test.That(t, n.connState.provisioningMode, test.ShouldBeTrue)
	test.That(t, n.connState.getProvisioningBluetooth(), test.ShouldBeTrue)

	err = n.StopProvisioning()
	test.That(t, err, test.ShouldBeNil)

	// Validate networking state from after stopping provisioning flow.
	test.That(t, n.connState.provisioningMode, test.ShouldBeFalse)
	test.That(t, n.connState.getProvisioningBluetooth(), test.ShouldBeFalse)

	/*
		Case 2: Fail to start bluetooth provisioning.
	*/
	bsm.shouldFailToStart = true

	err = n.StartProvisioning(ctx, inputChan)
	test.That(t, err, test.ShouldNotBeNil)

	// Validate networking state from after failing to start the provisioning flow.
	test.That(t, n.connState.provisioningMode, test.ShouldBeFalse)
	test.That(t, n.connState.getProvisioningBluetooth(), test.ShouldBeFalse)

	/*
		Case 3: Fail to wait for credentials after starting bluetooth provisioning.
	*/
	bsm.shouldFailToStart = false
	bsm.shouldFailToWaitForCredentials = true

	err = n.StartProvisioning(ctx, inputChan)
	test.That(t, err, test.ShouldBeNil) // Desired behavior is up to discussion.

	// Validate networking state from after failing to wait for credentials.
	test.That(t, n.connState.provisioningMode, test.ShouldBeTrue)
	test.That(t, n.connState.getProvisioningBluetooth(), test.ShouldBeTrue)

	err = n.StopProvisioning() // Need to clean up because it is technically still active.
	test.That(t, err, test.ShouldBeNil)

	/*
		Case 4: Fail to stop bluetooth provisioning.
	*/
	bsm.shouldFailToStart = false
	bsm.shouldFailToWaitForCredentials = false
	bsm.shouldFailToStop = true

	err = n.StartProvisioning(ctx, inputChan)
	test.That(t, err, test.ShouldBeNil)

	// Validate networking state from after starting provisioning flow.
	test.That(t, n.connState.provisioningMode, test.ShouldBeTrue)
	test.That(t, n.connState.getProvisioningBluetooth(), test.ShouldBeTrue)

	err = n.StopProvisioning()
	test.That(t, err, test.ShouldNotBeNil)

	// Validate networking state from after failing to stop the provisioning flow.
	test.That(t, n.connState.provisioningMode, test.ShouldBeTrue)
	test.That(t, n.connState.getProvisioningBluetooth(), test.ShouldBeTrue)

	/*
		Case 5: Successfully stop bluetooth provisioning.
	*/
	bsm.shouldFailToStop = false

	err = n.StopProvisioning()
	test.That(t, err, test.ShouldBeNil)

	// Validate networking state from after failing to stop the provisioning flow.
	test.That(t, n.connState.provisioningMode, test.ShouldBeFalse)
	test.That(t, n.connState.getProvisioningBluetooth(), test.ShouldBeFalse)

	// Need to add a way of restoring WiFi connection to existing before exiting from this test suite.
}

func newNetworkingWithBluetoothServiceMock(t *testing.T, ctx context.Context, logger logging.Logger) (*Networking, *bluetoothServiceMock) {
	cfg := utils.DefaultConfig()
	cfg.NetworkConfiguration.HotspotSSID = "viam-setup"
	subsystem := NewSubsystem(ctx, logger, cfg)
	networking, ok := subsystem.(*Networking)
	test.That(t, ok, test.ShouldBeTrue)
	bsm := &bluetoothServiceMock{}
	networking.bluetoothService = bsm
	test.That(t, networking.init(ctx), test.ShouldBeNil)
	return networking, bsm
}

type bluetoothServiceMock struct {
	shouldFailToStart              bool
	shouldFailToWaitForCredentials bool
	shouldFailToStop               bool
}

func (bsm *bluetoothServiceMock) start(
	_ context.Context,
	_, _ bool,
	_ chan<- userInput,
) error {
	if bsm.shouldFailToStart {
		return errors.New("mock error: fail to start")
	}
	return nil
}

func (bsm *bluetoothServiceMock) stop() error {
	if bsm.shouldFailToStop {
		return errors.New("mock error: fail to stop")
	}
	return nil
}
