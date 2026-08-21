package utils

import (
	"context"
	"time"

	"go.viam.com/rdk/logging"
)

// SystemBootTime returns the time at which the operating system last booted.
func SystemBootTime() (time.Time, error) {
	return systemBootTime()
}

// SystemIsShuttingDown reports whether the whole system (not just this service) is on
// its way down, so a termination signal can be attributed to a reboot or poweroff
// rather than to a restart of the agent alone. Returns false when it cannot be
// determined, including on platforms where we have no way to ask.
func SystemIsShuttingDown(ctx context.Context, logger logging.Logger) bool {
	return systemIsShuttingDown(ctx, logger)
}
