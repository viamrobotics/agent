package utils

import (
	"os/exec"

	"go.viam.com/rdk/logging"
)

func PlatformProcSettings(cmd *exec.Cmd) {}

func PlatformKill(logger logging.Logger, cmd *exec.Cmd) {}
