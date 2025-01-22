package main

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/viamrobotics/agent"
	"github.com/viamrobotics/agent/subsystems/provisioning"
	// register-only.
	_ "github.com/viamrobotics/agent/subsystems/syscfg"
	"github.com/viamrobotics/agent/subsystems/viamserver"
	"go.viam.com/utils"
)

func main() {
	commonMain()
}

// platform-specific provisioning logic.
func runPlatformProvisioning(ctx context.Context, manager *agent.Manager, loadConfigErr error, absConfigPath string) {
	// If the local /etc/viam.json config is corrupted, invalid, or missing (due to a new install), we can get stuck here.
	// Rename the file (if it exists) and wait to provision a new one.
	if !errors.Is(loadConfigErr, fs.ErrNotExist) {
		if err := os.Rename(absConfigPath, absConfigPath+".old"); err != nil {
			// if we can't rename the file, we're up a creek, and it's fatal
			globalLogger.Error(errors.Wrapf(err, "removing invalid config file %s", absConfigPath))
			globalLogger.Error("unable to continue with provisioning, exiting")
			manager.CloseAll()
			return
		}
	}

	// We manually start the provisioning service to allow the user to update it and wait.
	// The user may be updating it soon, so better to loop quietly than to exit and let systemd keep restarting infinitely.
	globalLogger.Infof("main config file %s missing or corrupt, entering provisioning mode", absConfigPath)

	if err := manager.StartSubsystem(ctx, provisioning.SubsysName); err != nil {
		if errors.Is(err, agent.ErrSubsystemDisabled) {
			globalLogger.Warn("provisioning subsystem disabled, please manually update /etc/viam.json and connect to internet")
		} else {
			globalLogger.Error(errors.Wrapf(err,
				"could not start provisioning subsystem, please manually update /etc/viam.json and connect to internet"))
			manager.CloseAll()
			return
		}
	}

	for {
		globalLogger.Warn("waiting for user provisioning")
		if !utils.SelectContextOrWait(ctx, time.Second*10) {
			manager.CloseAll()
			return
		}
		if err := manager.LoadConfig(absConfigPath); err == nil {
			break
		}
	}
}

// platform-specific path setup.
func setupProvisioningPaths(opts agentOpts) string {
	// pass the provisioning path arg to the subsystem
	absProvConfigPath, err := filepath.Abs(opts.ProvisioningConfig)
	exitIfError(err)
	provisioning.ProvisioningConfigFilePath = absProvConfigPath
	globalLogger.Infof("provisioning config file path: %s", absProvConfigPath)

	// tie the manager config to the viam-server config
	absConfigPath, err := filepath.Abs(opts.Config)
	exitIfError(err)
	viamserver.ConfigFilePath = absConfigPath
	provisioning.AppConfigFilePath = absConfigPath
	globalLogger.Infof("config file path: %s", absConfigPath)

	return absConfigPath
}

// return true if this error is safe to ignore on this platform.
func ignoredSignal(sig os.Signal) bool {
	// ignore SIGURG entirely, it's used for real-time scheduling notifications
	return sig == syscall.SIGURG
}
