package utils

import (
	"testing"
	"time"

	"go.viam.com/rdk/logging"
	"go.viam.com/test"
)

func TestSystemBootTime(t *testing.T) {
	bootTime, err := SystemBootTime()
	test.That(t, err, test.ShouldBeNil)

	uptime := time.Since(bootTime)
	test.That(t, uptime, test.ShouldBeGreaterThan, time.Duration(0))
	// A machine reporting an uptime of decades has given us a bogus boot time.
	test.That(t, uptime, test.ShouldBeLessThan, time.Hour*24*365*10)
}

func TestSystemIsShuttingDown(t *testing.T) {
	// The machine running the tests is not on its way down, and neither systemd being
	// absent nor it reporting some other state should be mistaken for a shutdown.
	test.That(t, SystemIsShuttingDown(t.Context(), logging.NewTestLogger(t)), test.ShouldBeFalse)
}
