package utils

import (
	"context"
	"os/exec"

	"go.viam.com/rdk/logging"
)

// PlatformSubprocessSettings sets platform-specific subprocess settings.
func PlatformSubprocessSettings(cmd *exec.Cmd) {}

// PlatformKill does SIGKILL if available for the platform.
func PlatformKill(logger logging.Logger, cmd *exec.Cmd) {}

func WaitOnline(logger logging.Logger, ctx context.Context) {
	logger.Warn("WaitOnline not available on windows yet")
}
