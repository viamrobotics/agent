package main

import (
	"context"
	"io/fs"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/viamrobotics/agent"
	"github.com/viamrobotics/agent/subsystems/networking"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
	goutils "go.viam.com/utils"
)

func main() {
	commonMain()
}

func waitOnline(logger logging.Logger, timeoutCtx context.Context) {
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

// tries to run provisioning, returns false if failed + main function should exit.
func runPlatformProvisioning(ctx context.Context, cfg utils.AgentConfig, manager *agent.Manager, err error) bool {
	if cfg.AdvancedSettings.DisableNetworkConfiguration {
		globalLogger.Errorf("Cannot read %s and network configuration is disabled. Please correct and restart viam-agent.",
			utils.AppConfigFilePath)
		return false
	}

	// If the local /etc/viam.json config is corrupted, invalid, or missing (due to a new install), we can get stuck here.
	// Rename the file (if it exists) and wait to provision a new one.
	if !errors.Is(err, fs.ErrNotExist) {
		globalLogger.Error(errors.Wrapf(err, "reading %s", utils.AppConfigFilePath))
		globalLogger.Warn("renaming %s to %s.old", utils.AppConfigFilePath, utils.AppConfigFilePath)
		if err := os.Rename(utils.AppConfigFilePath, utils.AppConfigFilePath+".old"); err != nil {
			// if we can't rename the file, we're up a creek, and it's fatal
			globalLogger.Error(errors.Wrapf(err, "removing invalid config file %s", utils.AppConfigFilePath))
			globalLogger.Error("unable to continue with provisioning, exiting")
			return false
		}
	}

	// We manually start the provisioning service to allow the user to update it and wait.
	// The user may be updating it soon, so better to loop quietly than to exit and let systemd keep restarting infinitely.
	globalLogger.Infof("machine credentials file %s missing or corrupt, entering provisioning mode", utils.AppConfigFilePath)

	if err := manager.StartSubsystem(ctx, networking.SubsysName); err != nil {
		globalLogger.Error(errors.Wrapf(err, "could not start networking subsystem, "+
			"please manually update /etc/viam.json and connect to internet"))
		return false
	}

	for {
		globalLogger.Warn("waiting for user provisioning")
		if !goutils.SelectContextOrWait(ctx, time.Second*10) {
			return false
		}
		if err := manager.LoadAppConfig(); err == nil {
			break
		}
	}
	return true
}
