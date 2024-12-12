package utils

import (
	"os/exec"
	"syscall"

	"go.viam.com/rdk/logging"
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
