package main

import (
	"context"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/pkg/errors"
	goutils "go.viam.com/utils"
)

func main() {
	commonMain()
}

func waitOnline(timeoutCtx context.Context) {
	for {
		cmd := exec.CommandContext(timeoutCtx, "systemctl", "is-active", "network-online.target")
		_, err := cmd.CombinedOutput()

		if err == nil {
			break
		}

		if e := (&exec.ExitError{}); !errors.As(err, &e) {
			// if it's not an ExitError, that means it didn't even start, so bail out
			globalLogger.Error(errors.Wrap(err, "running 'systemctl is-active network-online.target'"))
			break
		}
		if !goutils.SelectContextOrWait(timeoutCtx, time.Second) {
			break
		}
	}
}

func ignoredSignal(sig os.Signal) bool {
	// ignore SIGURG entirely, it's used for real-time scheduling notifications
	return sig == syscall.SIGURG
}
