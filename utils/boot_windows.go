package utils

import (
	"context"
	"time"

	"go.viam.com/rdk/logging"
	"golang.org/x/sys/windows"
)

func systemBootTime() (time.Time, error) {
	return time.Now().Add(-windows.DurationSinceBoot()), nil
}

func systemIsShuttingDown(_ context.Context, _ logging.Logger) bool {
	// A system shutdown reaches us as an svc.Shutdown control request instead, which
	// the service handler in cmd/viam-agent records directly.
	return false
}
