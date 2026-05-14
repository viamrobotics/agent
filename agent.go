// Package agent is the viam-agent itself. It contains code to install/update the systemd service as well.
package agent

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
)

// systemManager is implemented by SystemdManager on Linux and LaunchdManager on MacOS. It
// is unimplemented on Windows.
type systemManager interface {
	IsAvailable(ctx context.Context) error
	InstallService(ctx context.Context, serviceName string, serviceFileContents []byte) (string, bool, error)
	Enable(ctx context.Context, serviceName string) error
}

// Install is directly executed from main() when --install is passed.
func Install(ctx context.Context, logger logging.Logger, sManager systemManager) error {
	// Check for system manager availability.
	err := sManager.IsAvailable(ctx)
	if err != nil {
		return errw.Wrap(err, "can only install on systems using system managers")
	}

	// Create/check required folder structure exists.
	if err := utils.InitPaths(logger); err != nil {
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
		logger.Infow("installing self and adding symlink", "cachePath", expectedCachePath, "binPath", expectedBinPath)
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

	serviceFilePath, newInstall, err := sManager.InstallService(ctx, serviceName, serviceFileContents)
	if err != nil {
		return errw.Wrap(err, "installing system service")
	}
	if newInstall {
		if err := sManager.Enable(ctx, serviceName); err != nil {
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
