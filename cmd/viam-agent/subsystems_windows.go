package main

import (
	"context"
	"os"

	"github.com/viamrobotics/agent"
)

func runPlatformProvisioning(context.Context, *agent.Manager, error, string) {
	globalLogger.Warn("provisioning not available on windows yet")
}

func setupProvisioningPaths(agentOpts) string { return "" }

func ignoredSignal(os.Signal) bool { return false }
