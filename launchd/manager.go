// Package launchd provides helpers for the com.viam.agent launchd daemon.
package launchd

import (
	"context"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
)

const systemLaunchDaemonDir = "/Library/LaunchDaemons"

// Annoying workaround to allow embedding LaunchdExecutor in LaunchdManager w/o
// allowing it to be modified from outside the module.
type privateExecutor = LaunchdExecutor

// LaunchdManager provides methods for making high-level changes to the viam-agent launchd daemon.
type LaunchdManager struct {
	privateExecutor
	logger logging.Logger
}

func NewLaunchdManager(logger logging.Logger) *LaunchdManager {
	return &LaunchdManager{
		privateExecutor: realLaunchdExecutor{},
		logger:          logger,
	}
}

func (l *LaunchdManager) InstallService(ctx context.Context, serviceName string, serviceFileContents []byte) (string, bool, error) {
	serviceFilePath := filepath.Join(systemLaunchDaemonDir, serviceName+".plist")
	var newInstall bool
	if _, err := os.Stat(serviceFilePath); err != nil {
		newInstall = false
	}

	l.logger.Infof("Writing launchd service file to %s", serviceFilePath)

	newFile, err := utils.WriteFileIfNew(serviceFilePath, serviceFileContents)
	if err != nil {
		return "", false, errors.Wrapf(err, "writing launchd service file %s", serviceFilePath)
	}

	if !newFile {
		if err := l.Bootout(ctx, serviceName); err != nil {
			// Booting out may return an error if the system was never bootstrapped. Log and
			// continue here in that case.
			l.logger.Infow("Ignoring error from bootout", "error", err.Error())
		}
	}
	if err := l.Bootstrap(ctx, serviceFilePath); err != nil {
		return "", false, err
	}

	if err := utils.SyncFS(serviceFilePath); err != nil {
		return "", false, err
	}

	return serviceFilePath, newInstall, nil
}
