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
		Case 1: Successfully start and stop bluetooth provisioning.
	*/
	bsm.shouldFailToStart = false
	bsm.shouldFailToStop = false
	test.That(t, n.connState.getProvisioning(), test.ShouldBeFalse)
	err := n.StartProvisioning(ctx, inputChan)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, n.connState.getProvisioning(), test.ShouldBeTrue)
	err = n.StopProvisioning()
	test.That(t, err, test.ShouldBeNil)
	test.That(t, n.connState.getProvisioning(), test.ShouldBeFalse)

	/*
		Case 2: Fail to start bluetooth provisioning, but hotspot should still work.
	*/
	bsm.shouldFailToStart = true
	err = n.StartProvisioning(ctx, inputChan)
	test.That(t, err, test.ShouldNotBeNil)
	test.That(t, n.connState.getProvisioning(), test.ShouldBeTrue)
	err = n.StopProvisioning()
	test.That(t, err, test.ShouldBeNil)
	test.That(t, n.connState.getProvisioning(), test.ShouldBeFalse)

	/*
		Case 3: Fail to stop bluetooth provisioning after starting provisioning.
	*/
	bsm.shouldFailToStart = false
	bsm.shouldFailToStop = true
	err = n.StartProvisioning(ctx, inputChan)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, n.connState.getProvisioning(), test.ShouldBeTrue)
	err = n.StopProvisioning()
	test.That(t, err, test.ShouldNotBeNil)
	test.That(t, err.Error(), test.ShouldContainSubstring, "mock error: fail to stop")
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
	shouldFailToStart bool
	shouldFailToStop  bool
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

func (bsm *bluetoothServiceMock) healthy() bool {
	return true
}
