//go:build !linux && !windows

package main

import (
	"context"
	"os"
	"runtime"

	"github.com/viamrobotics/agent"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
)

func main() {
	commonMain()
}

func runPlatformProvisioning(_ context.Context, _ utils.AgentConfig, _ *agent.Manager, _ error) bool {
	return false
}

func waitOnline(logger logging.Logger, _ context.Context) {
	logger.Debugf("WaitOnline not available on %s yet", runtime.GOOS)
}

func ignoredSignal(_ os.Signal) bool {
	return false
}
