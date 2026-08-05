package syscfg

import (
	"testing"

	"go.viam.com/test"
)

func TestUpgradeState(t *testing.T) {
	var state upgradeState
	test.That(t, state.running(), test.ShouldBeFalse)

	done := state.begin()
	test.That(t, state.running(), test.ShouldBeTrue)

	done()
	test.That(t, state.running(), test.ShouldBeFalse)
}
