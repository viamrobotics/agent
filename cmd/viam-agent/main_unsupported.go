//go:build !linux && !windows

package main

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/viamrobotics/agent"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
)

func main() {
	//nolint: forbidigo
	fmt.Printf("viam-agent is not supported on %v\n", runtime.GOOS)
	os.Exit(1)
	// Call commonMain to avoid tripping a bunch of lints for unused code.
	// Execution will never actually get here.
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
