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
	"slices"
	"strings"
	"time"

	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
)

const (
	serviceFileDir  = "/usr/local/lib/systemd/system"
	fallbackFileDir = "/etc/systemd/system"
	serviceFileName = "viam-agent.service"
)

//go:embed viam-agent.service
var serviceFileContents []byte

// InstallNewVersion runs the newly downloaded binary's Install() for installation of systemd files and the like.
func InstallNewVersion(ctx context.Context, logger logging.Logger) (bool, error) {
	if runtime.GOOS == "windows" {
		// windows doesn't have systemctl so we don't do a postinstall yet.
		return true, nil
	}
	expectedPath := filepath.Join(utils.ViamDirs["bin"], SubsystemName)

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

func goarchToOsArch(goarch string) string {
	switch goarch {
	case "arm64":
		return "aarch64"
	case "amd64":
		return "x86_64"
	}
	return ""
}

// Install is directly executed from main() when --install is passed.
func Install(logger logging.Logger) error {
	// Check for systemd
	cmd := exec.Command("systemctl", "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errw.Wrapf(err, "can only install on systems using systemd, but 'systemctl --version' returned errors %s", output)
	}

	// Create/check required folder structure exists.
	if err := utils.InitPaths(); err != nil {
		return err
	}

	// If this is a brand new install, we want to copy ourselves into the version
	// cache and install a symlink.
	expectedBinPath := filepath.Join(utils.ViamDirs["bin"], SubsystemName)
	arch := goarchToOsArch(runtime.GOARCH)
	if arch == "" {
		return fmt.Errorf("could not determine platform arch mapping for GOARCH %s", runtime.GOARCH)
	}
	expectedCachePath := filepath.Join(utils.ViamDirs["cache"], strings.Join([]string{SubsystemName, utils.Version, arch}, "-"))
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
		versionCache := NewVersionCache(logger)
		trimmedVersion, _ := strings.CutPrefix(utils.Version, "v")
		versionCache.ViamAgent.CurrentVersion = trimmedVersion
		versionCache.ViamAgent.Versions[trimmedVersion] = &VersionInfo{
			Version:      trimmedVersion,
			UnpackedPath: expectedCachePath,
			DlPath:  expectedCachePath,
			SymlinkPath:  expectedBinPath,
			Installed:    time.Now(),
		}
		if err := versionCache.save(); err != nil {
			return errw.Wrap(err, "writing version cache to disk")
		}
	}

	serviceFilePath, removeOldFile, err := getServiceFilePath(logger)
	if err != nil {
		return errw.Wrap(err, "getting service file path")
	}

	// use this later to avoid re-enabling an existing agent service a user might have disabled
	_, err = os.Stat(serviceFilePath)
	newInstall := err != nil

	logger.Infof("writing systemd service file to %s", serviceFilePath)

	newFile, err := utils.WriteFileIfNew(serviceFilePath, serviceFileContents)
	if err != nil {
		return errw.Wrapf(err, "writing systemd service file %s", serviceFilePath)
	}

	if removeOldFile {
		oldPath := filepath.Join(fallbackFileDir, serviceFileName)
		logger.Warn("Removing system service file %s in favor of vendor file at %s", oldPath, serviceFilePath)
		logger.Warn("If you customized this file, please run 'systemctl edit viam-agent' and create overrides there")
		if err := os.RemoveAll(oldPath); err != nil {
			logger.Warn(errw.Wrapf(err, "removing old service file %s, please delete manually", oldPath))
		}
	}

	if newFile {
		cmd = exec.Command("systemctl", "daemon-reload")
		output, err = cmd.CombinedOutput()
		if err != nil {
			return errw.Wrapf(err, "running 'systemctl daemon-reload' output: %s", output)
		}
	}

	if newInstall {
		logger.Infof("enabling systemd viam-agent service")
		cmd = exec.Command("systemctl", "enable", "viam-agent")
		output, err = cmd.CombinedOutput()
		if err != nil {
			return errw.Wrapf(err, "running 'systemctl enable viam-agent' output: %s", output)
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

	return errors.Join(utils.SyncFS("/etc"), utils.SyncFS(serviceFilePath), utils.SyncFS(utils.ViamDirs["viam"]))
}

func inSystemdPath(path string, logger logging.Logger) bool {
	cmd := exec.Command("systemd-path", "systemd-search-system-unit")
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Warn(errw.Wrapf(err, "running 'systemd-path systemd-search-system-unit' output: %s", output))
		return false
	}
	searchPaths := strings.Split(strings.TrimSpace(string(output)), ":")
	return slices.Contains(searchPaths, path)
}

func getServiceFilePath(logger logging.Logger) (string, bool, error) {
	serviceFilePath := filepath.Join(serviceFileDir, serviceFileName)
	_, err := os.Stat(serviceFilePath)
	if err == nil {
		// file is already in place, we should be good
		return serviceFilePath, false, nil
	}
	if !errw.Is(err, fs.ErrNotExist) {
		// unknown error
		return "", false, err
	}
	oldFilePath := filepath.Join(fallbackFileDir, serviceFileName)

	// see if we can migrate to the local path
	if !inSystemdPath(serviceFileDir, logger) {
		logger.Warnf("Systemd does not have %s in its unit search path, installing directly to %s", serviceFileDir, fallbackFileDir)
		return oldFilePath, false, nil
	}

	// migrate old file if it exists
	_, err = os.Stat(oldFilePath)
	if err == nil {
		return serviceFilePath, true, nil
	}
	if !errw.Is(err, fs.ErrNotExist) {
		// unknown error when checking old service file path
		return "", false, err
	}

	// new install, so there was nothing to migrate
	return serviceFilePath, false, nil
}
