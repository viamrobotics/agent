// Package agent is the viam-agent itself. It contains code to install/update the systemd service as well.
//
//nolint:goconst
package agent

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
)

const (
	serviceName = "viam-agent.service"
)

//go:embed viam-agent.service
var serviceFileContents []byte

type systemdManager interface {
	IsAvailable() error
	InstallService(serviceName string, serviceFileContents []byte) (string, bool, error)
	Enable(serviceName string) error
}

// InstallNewVersion runs the newly downloaded binary's Install() for installation of systemd files and the like.
func InstallNewVersion(ctx context.Context, logger logging.Logger) (bool, error) {
	if runtime.GOOS == "windows" {
		// windows doesn't have systemctl so we don't do a postinstall yet.
		return true, nil
	}
	expectedPath := filepath.Join(utils.ViamDirs.Bin, SubsystemName)

	// Run the newly updated version to install systemd and other service files.
	//nolint:gosec
	cmd := exec.Command(expectedPath, "--install")
	output, err := cmd.CombinedOutput()
	logger.Info("running viam-agent --install for new version")
	logger.Info(string(output))
	if err != nil {
		return false, errw.Wrapf(err, "running post install step %s", output)
	}
	return true, nil
}

// Install is directly executed from main() when --install is passed.
func Install(logger logging.Logger, sdManager systemdManager) error {
	// Check for systemd
	err := sdManager.IsAvailable()
	if err != nil {
		return errw.Wrap(err, "can only install on systems using systemd")
	}

	// Create/check required folder structure exists.
	if err := utils.InitPaths(); err != nil {
		return err
	}

	// If this is a brand new install, we want to copy ourselves into the version
	// cache and install a symlink.
	expectedBinPath := filepath.Join(utils.ViamDirs.Bin, SubsystemName)
	arch := utils.GoArchToOSArch(runtime.GOARCH)
	if arch == "" {
		return fmt.Errorf("could not determine platform arch mapping for GOARCH %s", runtime.GOARCH)
	}
	expectedCachePath := filepath.Join(utils.ViamDirs.Cache, strings.Join([]string{SubsystemName, "v" + utils.Version, arch}, "-"))
	curPath, err := os.Executable()
	if err != nil {
		return errw.Wrap(err, "getting path to self")
	}

	isExpected, err := utils.CheckIfSame(expectedCachePath, expectedBinPath)
	if err != nil {
		return errw.Wrap(err, "checking if installed viam-agent is in expected state")
	}

	if !isExpected {
		logger.Infof("installing to %s and adding a symlink at %s", expectedCachePath, expectedBinPath)
		err := utils.AtomicCopy(expectedCachePath, curPath)
		if err != nil {
			return errw.Wrap(err, "installing self into cache directory")
		}
		if err := os.Remove(expectedBinPath); err != nil && !errw.Is(err, fs.ErrNotExist) {
			return errw.Wrapf(err, "removing symlink/file at %s", expectedBinPath)
		}
		if err := os.Symlink(expectedCachePath, expectedBinPath); err != nil {
			return errw.Wrapf(err, "installing symlink at %s", expectedBinPath)
		}

		if !VersionCacheExists() {
			// Version cache doesn't exist, so assume this is a fresh install and write
			// a minimal version cache to avoid downloading a copy of this same version
			// on first run.
			versionCache := NewVersionCache(logger)
			trimmedVersion, _ := strings.CutPrefix(utils.Version, "v")
			versionCache.ViamAgent.CurrentVersion = trimmedVersion
			versionCache.ViamAgent.Versions[trimmedVersion] = &VersionInfo{
				Version:      trimmedVersion,
				UnpackedPath: expectedCachePath,
				DlPath:       expectedCachePath,
				SymlinkPath:  expectedBinPath,
				Installed:    time.Now(),
			}
			if err := versionCache.save(); err != nil {
				return errw.Wrap(err, "writing version cache to disk")
			}
		}
	}

	serviceFilePath, newInstall, err := sdManager.InstallService(serviceName, serviceFileContents)
	if err != nil {
		return errw.Wrap(err, "installing systemd service")
	}
	if newInstall {
		if err := sdManager.Enable("viam-agent"); err != nil {
			return err
		}
	}

	_, err = os.Stat("/etc/viam.json")
	if err != nil {
		if errw.Is(err, fs.ErrNotExist) {
			logger.Warn("No config file found at /etc/viam.json, please install one before running viam-agent service.")
		} else {
			return errw.Wrap(err, "reading /etc/viam.json")
		}
	}

	logger.Info("Install complete.")

	return errors.Join(utils.SyncFS("/etc"), utils.SyncFS(serviceFilePath), utils.SyncFS(utils.ViamDirs.Viam))
}
