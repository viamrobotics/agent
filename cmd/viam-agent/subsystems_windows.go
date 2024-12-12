package main

import (
	"context"
	"os"

	"github.com/viamrobotics/agent"
)

func runPlatformProvisioning(ctx context.Context, manager *agent.Manager, loadConfigErr error, absConfigPath string) {
	globalLogger.Warn("provisioning not available on windows yet")
}

func setupProvisioningPaths(opts agentOpts) string { return "" }

func ignoredSignal(sig os.Signal) bool { return false }
