// Package launchd provides helpers for the com.viam.agent launchd service.
package launchd

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
)

const (
	systemLaunchDaemonDir = "/Library/LaunchDaemons"
	// Should match ExitTimeOut in com.viam.agent.plist.
	launchdExitTimeOut = 4 * time.Minute
)

// Annoying workaround to allow embedding LaunchdExecutor in LaunchdManager w/o
// allowing it to be modified from outside the module.
type privateExecutor = LaunchdExecutor

// LaunchdManager provides methods for making high-level changes to the viam-agent launchd
// service.
type LaunchdManager struct {
	privateExecutor
	serviceDir string
	logger     logging.Logger
}

func NewLaunchdManager(logger logging.Logger) *LaunchdManager {
	return &LaunchdManager{
		privateExecutor: realLaunchdExecutor{},
		serviceDir:      systemLaunchDaemonDir,
		logger:          logger,
	}
}

func (l *LaunchdManager) InstallService(ctx context.Context, serviceName string, serviceFileContents []byte) (string, bool, error) {
	serviceFilePath := filepath.Join(l.serviceDir, serviceName+".plist")
	var newInstall bool
	if _, err := os.Stat(serviceFilePath); err != nil {
		newInstall = true
	}

	newFile, err := utils.WriteFileIfNew(serviceFilePath, serviceFileContents)
	if err != nil {
		return "", false, errors.Wrapf(err, "writing launchd plist file %s", serviceFilePath)
	}

	if newFile {
		l.logger.Infof("Wrote new launchd plist file to %s", serviceFilePath)

		// We only need to "bootout" an existing service if this isn't a new installation.
		if !newInstall {
			// MacOS is different from Linux in that there is no `systemctl daemon-reload`
			// analog in launchd. To replace the .plist for a running launchd service, one needs
			// to "bootout" the existing service, which will both stop any running processes and
			// remove the plist file from launchd's program memory. That _stopping_ of
			// viam-agent and viam-server means we need to potentially wait a while here for the
			// service to no longer show up in `launchctl print`. Per the ExitTimeOut property
			// in com.viam.agent.plist, launchd will send SIGTERM to viam-agent and, if the
			// process is still running after 240s (4m), will send SIGKILL. We'll wait up to 4
			// minutes here.

			l.logger.Infof("Booting out old %s launchd service", serviceName)
			if err := l.Bootout(ctx, serviceName); err != nil {
				// Booting out may return an error if the system was never bootstrapped in the
				// first place or was manually removed by user. Log and continue here in that
				// case.
				l.logger.Infow("Ignoring error from bootout", "error", err.Error())
			}

			t := time.NewTimer(launchdExitTimeOut)
			var timesChecked int
			for {
				if l.IsServiceRemoved(ctx, serviceName) {
					break
				}
				select {
				case <-time.After(time.Second):
					timesChecked++
					if timesChecked%10 == 0 {
						l.logger.Infof("Waited %d seconds for existing service to stop and be removed", timesChecked)
					}
				case <-t.C:
					return "", false, errors.Errorf("bootout failed to stop and remove existing service after %s",
						launchdExitTimeOut)
				case <-ctx.Done():
					return "", false, errors.WithMessage(ctx.Err(), "bootout failed to stop and remove existing service")
				}
			}
			l.logger.Infof("Old %s launchd service booted out", serviceName)
		}

		if err := l.Bootstrap(ctx, serviceFilePath); err != nil {
			return "", false, err
		}

		l.logger.Infof("New %s launchd service bootstrapped", serviceName)
	}

	if err = l.Kickstart(ctx, serviceName, true /* killExisting */); err != nil {
		return "", false, err
	}

	l.logger.Infof("%s launchd service restarted", serviceName)

	return serviceFilePath, newInstall, nil
}
