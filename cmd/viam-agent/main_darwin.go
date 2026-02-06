package main

import (
	"context"
	"os"

	"github.com/viamrobotics/agent"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
)

func main() {
	commonMain()
}

func waitOnline(logger logging.Logger, _ context.Context) {
	logger.Debug("WaitOnline not available on MacOS yet")
}

func ignoredSignal(_ os.Signal) bool {
	return false
}

func runPlatformProvisioning(_ context.Context, _ utils.AgentConfig, _ *agent.Manager, _ error) bool {
	return false
}
