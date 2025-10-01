// Package systemd provides helpers to manipulate systemd services that are
// specifict to viam-agent's needs.
package systemd

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/pkg/errors"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
)

const (
	defaultServiceFileDir  = "/usr/local/lib/systemd/system"
	defaultFallbackFileDir = "/etc/systemd/system"
)

type systemdDirs struct {
	serviceFileDir  string
	fallbackFileDir string
}

// Annoying workaround to allow embedding SystemdExecutor in SystemdManager w/o
// allowing it to be modified from outside the module.
type privateExecutor = SystemdExecutor

// SystemdManager provides methods for making high-level changes to systemd
// services.
type SystemdManager struct {
	privateExecutor
	dirs   systemdDirs
	logger logging.Logger
}

// SystemdManagerOption is a type used to configure the [SystemdManager]
// returned from [NewSystemdManager].
type SystemdManagerOption func(*SystemdManager)

// WithExecutor configures the created [SystemdManager] with a custom
// [SystemdExecutor] implementation. Should only be used for testing.
func WithExecutor(executor SystemdExecutor) SystemdManagerOption {
	return func(manager *SystemdManager) {
		manager.privateExecutor = executor
	}
}

// WithDirs configures the created [SystemdManager] with custom service file
// search paths. Should only be used for testing.
func WithDirs(serviceFileDir, fallbackFileDir string) SystemdManagerOption {
	return func(manager *SystemdManager) {
		manager.dirs.serviceFileDir = serviceFileDir
		manager.dirs.fallbackFileDir = fallbackFileDir
	}
}

func NewSystemdManager(logger logging.Logger, opts ...SystemdManagerOption) *SystemdManager {
	manager := &SystemdManager{
		logger:          logger,
		privateExecutor: realSystemdExecutor{},
		dirs: systemdDirs{
			serviceFileDir:  defaultServiceFileDir,
			fallbackFileDir: defaultFallbackFileDir,
		},
	}
	for _, opt := range opts {
		opt(manager)
	}
	return manager
}

// InstallService creates or updates a service file. If a service file with the
// same name exists in an deprecated location it will also automatically remove
// the old file. It returns the path the installed service file if it exists.
// It also returns true if the install was successful and the service did not
// already exist.
func (s *SystemdManager) InstallService(serviceName string, serviceFileContents []byte) (string, bool, error) {
	serviceFileName := serviceName + ".service"
	serviceFilePath, removeOldFile, err := s.getServiceFilePath(serviceFileName)
	if err != nil {
		return "", false, err
	}

	// Track if the service file already existed an any way. Use this later to
	// avoid reenabling a service the user disabled.
	newInstall := !removeOldFile
	if newInstall {
		_, err = os.Stat(serviceFilePath)
		newInstall = err != nil
	}

	s.logger.Infof("writing systemd service file to %s", serviceFilePath)

	newFile, err := utils.WriteFileIfNew(serviceFilePath, serviceFileContents)
	if err != nil {
		return "", false, errors.Wrapf(err, "writing systemd service file %s", serviceFilePath)
	}

	if removeOldFile {
		oldPath := filepath.Join(s.dirs.fallbackFileDir, serviceFileName)
		s.logger.Warn("Removing system service file %s in favor of vendor file at %s", oldPath, serviceFilePath)
		s.logger.Warn("If you customized this file, please run 'systemctl edit viam-agent' and create overrides there")
		if err := os.RemoveAll(oldPath); err != nil {
			s.logger.Warn(errors.Wrapf(err, "removing old service file %s, please delete manually", oldPath))
		}
	}

	if newFile {
		if err := s.DaemonReload(); err != nil {
			return "", false, err
		}
	}

	if err := utils.SyncFS(serviceFilePath); err != nil {
		return "", false, err
	}

	return serviceFilePath, newInstall, nil
}

// getServiceFilePath checks if a file for the named service exists within
// systemd in one or more expected directories. On success it returns the path
// to the first located service file. On failure it returns an empty string.
// The second return value indicates whether the located file was in the
// previous path and a migration should be performed.
func (s *SystemdManager) getServiceFilePath(serviceFile string) (string, bool, error) {
	serviceFilePath := filepath.Join(s.dirs.serviceFileDir, serviceFile)
	_, err := os.Stat(serviceFilePath)
	if err == nil {
		// file is already in place, we should be good
		return serviceFilePath, false, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		// unknown error
		return "", false, err
	}
	oldFilePath := filepath.Join(s.dirs.fallbackFileDir, serviceFile)

	// Check if the new, preferred path is present in the systemd search path and
	// therefore a migration may need to be performed.
	searchPaths, err := s.SystemdSearchPaths()
	if err != nil {
		return "", false, err
	}
	if !slices.Contains(searchPaths, s.dirs.serviceFileDir) {
		s.logger.Warnf(
			"Systemd does not have %s in its unit search path, installing directly to %s",
			s.dirs.serviceFileDir,
			s.dirs.fallbackFileDir,
		)
		return oldFilePath, false, nil
	}

	// Check if the service exits in the old path. If it does then return the
	// _new_ path + a boolean indicating that a migration should be performed.
	_, err = os.Stat(oldFilePath)
	if err == nil {
		return serviceFilePath, true, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		// unknown error when checking old service file path
		return "", false, err
	}

	// new install, so there was nothing to migrate
	return serviceFilePath, false, nil
}
