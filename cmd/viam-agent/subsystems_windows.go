package main

import (
	"context"
	"os"
	"path/filepath"

	"github.com/viamrobotics/agent"
	"github.com/viamrobotics/agent/subsystems/viamserver"
)

func runPlatformProvisioning(context.Context, *agent.Manager, error, string) {
	globalLogger.Warn("provisioning not available on windows yet")
}

// platform-specific path setup.
func setupProvisioningPaths(opts agentOpts) string {
	// tie the manager config to the viam-server config
	absConfigPath, err := filepath.Abs(opts.Config)
	exitIfError(err)
	viamserver.ConfigFilePath = absConfigPath
	globalLogger.Infof("config file path: %s", absConfigPath)

	return absConfigPath
}

func ignoredSignal(os.Signal) bool { return false }
