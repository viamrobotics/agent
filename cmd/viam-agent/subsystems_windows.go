package main

import (
	"context"
	"os"

	"github.com/viamrobotics/agent"
)

func runPlatformProvisioning(ctx context.Context, manager *agent.Manager, loadConfigErr error, absConfigPath string) {
	panic("todo fancy error for provisioning on windows")
}

func setupProvisioningPaths(opts agentOpts) string { return "" }

func ignoredSignal(sig os.Signal) bool { return false }
