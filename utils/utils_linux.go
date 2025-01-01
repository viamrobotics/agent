package utils

import (
	"context"
	"os/exec"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"go.viam.com/rdk/logging"
	"go.viam.com/utils"
)

// PlatformSubprocessSettings sets platform-specific subprocess settings.
func PlatformSubprocessSettings(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// PlatformKill does SIGKILL if available for the platform.
func PlatformKill(logger logging.Logger, cmd *exec.Cmd) {
	err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if err != nil {
		logger.Error(err)
	}
}

// WaitOnline attempts to wait until the network comes up, with various bailout conditions.
func WaitOnline(logger logging.Logger, ctx context.Context) {
	for {
		cmd := exec.CommandContext(ctx, "systemctl", "is-active", "network-online.target")
		_, err := cmd.CombinedOutput()

		if err == nil {
			break
		}

		if e := (&exec.ExitError{}); !errors.As(err, &e) {
			// if it's not an ExitError, that means it didn't even start, so bail out
			logger.Error(errors.Wrap(err, "running 'systemctl is-active network-online.target'"))
			break
		}
		if !utils.SelectContextOrWait(ctx, time.Second) {
			break
		}
	}
}
