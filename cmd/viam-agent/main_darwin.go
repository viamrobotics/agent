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

func waitOnline(logger logging.Logger, timeoutCtx context.Context) {
	logger.Debug("WaitOnline not available on darwin yet")
}

func ignoredSignal(sig os.Signal) bool {
	// Ignore SIGURG and other signals that shouldn't cause us to exit
	return false
}

// tries to run provisioning, returns false if failed + main function should exit.
func runPlatformProvisioning(ctx context.Context, cfg utils.AgentConfig, manager *agent.Manager, err error) bool {
	return false
}
