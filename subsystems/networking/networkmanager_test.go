package networking

import (
	"context"
	"testing"

	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
	"go.viam.com/test"
)

func TestStartProvisioning(t *testing.T) {
	ctx := context.Background()
	logger := logging.NewTestLogger(t)
	n := newNetworkingMock(t, ctx, logger)
	test.That(t, n, test.ShouldNotBeNil)
	inputChan := make(chan userInput, 1)

	/*
		There is no variability in inputs passed to StartProvisioning, so
		networking state validation should suffice for unit testing.
	*/

	// Validate networking state from before provisioning flow.
	test.That(t, n.connState.provisioningMode, test.ShouldBeFalse)
	test.That(t, len(n.nets), test.ShouldEqual, 0)
	test.That(t, n.portalData, test.ShouldResemble, &portalData{})
	test.That(t, n.hotspotIsActive, test.ShouldBeFalse)
	test.That(t, n.bluetoothIsActive, test.ShouldBeFalse)

	err := n.StartProvisioning(ctx, inputChan)
	test.That(t, err, test.ShouldBeNil)

	// Validate networking state from after provisioning flow.
	test.That(t, n.connState.provisioningMode, test.ShouldBeTrue)
	test.That(t, len(n.nets), test.ShouldEqual, 0)
	var ui *userInput
	test.That(t, n.portalData.input, test.ShouldResemble, ui)
	test.That(t, n.hotspotIsActive, test.ShouldBeTrue)
	test.That(t, n.bluetoothIsActive, test.ShouldBeTrue)

	// Validate passing user inputs works.

}

func TestStopProvisioning(t *testing.T) {

}

func newNetworkingMock(t *testing.T, ctx context.Context, logger logging.Logger) *Networking {
	subsystem := NewSubsystem(ctx, logger, utils.DefaultConfig())
	networking, ok := subsystem.(*Networking)
	test.That(t, ok, test.ShouldBeTrue)
	networking.bluetoothService = &bluetoothServiceMock{}
	test.That(t, networking.init(ctx), test.ShouldBeNil)
	return networking
}

type bluetoothServiceMock struct {
}

func (bsm *bluetoothServiceMock) start(_ context.Context) error {
	return nil
}

func (bsm *bluetoothServiceMock) stop() error {
	return nil
}

func (bsm *bluetoothServiceMock) waitForCredentials(_ context.Context, _, _ bool, _ chan<- userInput) error {
	return nil
}
