// Package viamagent is the subsystem for the viam-agent itself. It contains code to install/update the systemd service as well.
package viamagent

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent"
	"github.com/viamrobotics/agent/subsystems"
	"github.com/viamrobotics/agent/subsystems/registry"
	"go.uber.org/zap"
	pb "go.viam.com/api/app/agent/v1"
)

func init() {
	registry.Register(subsysName, NewSubsystem, DefaultConfig)
}

const (
	subsysName      = "viam-agent"
	serviceFileDir  = "/usr/local/lib/systemd/system"
	fallbackFileDir = "/etc/systemd/system"
	serviceFileName = "viam-agent.service"
)

var (
	// versions embedded at build time.
	Version     = ""
	GitRevision = ""

	//go:embed viam-agent.service
	serviceFileContents []byte
	DefaultConfig       = &pb.DeviceSubsystemConfig{}
)

type agentSubsystem struct{}

func NewSubsystem(ctx context.Context, logger *zap.SugaredLogger, updateConf *pb.DeviceSubsystemConfig) (subsystems.Subsystem, error) {
	return agent.NewAgentSubsystem(ctx, subsysName, logger, &agentSubsystem{})
}

// Start does nothing (we're already running as we ARE the agent.)
func (a *agentSubsystem) Start(ctx context.Context) error {
	return nil
}

// Stop does nothing (special logic elsewhere handles self-restart.)
func (a *agentSubsystem) Stop(ctx context.Context) error {
	return nil
}

// HealthCheck does nothing (we're obviously runnning as we are the agent.)
func (a *agentSubsystem) HealthCheck(ctx context.Context) error {
	return nil
}

// Update here handles the post-update installation of systemd files and the like.
// The actual update check and download is done in the wrapper (agent.AgentSubsystem).
func (a *agentSubsystem) Update(ctx context.Context, cfg *pb.DeviceSubsystemConfig, newVersion bool) (bool, error) {
	if !newVersion {
		return false, nil
	}

	expectedPath := filepath.Join(agent.ViamDirs["bin"], subsysName)

	// Run the newly updated version to install systemd and other service files.
	//nolint:gosec
	cmd := exec.Command(expectedPath, "--install")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, errw.Wrapf(err, "running post install step %s", output)
	}
	//nolint:forbidigo
	fmt.Print(string(output))

	return true, nil
}

// GetVersion returns the version embedded at build time.
func GetVersion() string {
	if Version == "" {
		return "custom"
	}
	return Version
}

// GetRevision returns the git revision embedded at build time.
func GetRevision() string {
	if GitRevision == "" {
		return "unknown"
	}
	return GitRevision
}

func Install(logger *zap.SugaredLogger) error {
	// Check for systemd
	cmd := exec.Command("systemctl", "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errw.Wrapf(err, "can only install on systems using systemd, but 'systemctl --version' returned errors %s", output)
	}

	// Create/check required folder structure exists.
	if err := agent.InitPaths(); err != nil {
		return err
	}

	// If this is a brand new install, we want to symlink ourselves into place temporarily.
	expectedPath := filepath.Join(agent.ViamDirs["bin"], subsysName)
	curPath, err := os.Executable()
	if err != nil {
		return errw.Wrap(err, "getting path to self")
	}

	isSelf, err := agent.CheckIfSame(curPath, expectedPath)
	if err != nil {
		return errw.Wrap(err, "checking if installed viam-agent is myself")
	}

	if !isSelf {
		logger.Infof("adding a symlink to %s at %s", curPath, expectedPath)
		if err := os.Remove(expectedPath); err != nil && !errw.Is(err, fs.ErrNotExist) {
			return errw.Wrapf(err, "removing symlink/file at %s", expectedPath)
		}
		if err := os.Symlink(curPath, expectedPath); err != nil {
			return errw.Wrapf(err, "installing symlink at %s", expectedPath)
		}
	}

	serviceFilePath, removeOldFile, err := getServiceFilePath(logger)
	if err != nil {
		return errw.Wrap(err, "getting service file path")
	}

	//nolint:gosec
	if err := os.MkdirAll(filepath.Dir(serviceFilePath), 0o755); err != nil {
		return errw.Wrapf(err, "creating directory %s", filepath.Dir(serviceFilePath))
	}

	logger.Infof("writing systemd service file to %s", serviceFilePath)
	//nolint:gosec
	if err := os.WriteFile(serviceFilePath, serviceFileContents, 0o644); err != nil {
		return errw.Wrapf(err, "writing systemd service file %s", serviceFilePath)
	}

	if removeOldFile {
		oldPath := filepath.Join(fallbackFileDir, serviceFileName)
		logger.Warn("Removing system service file %s in favor of vendor file at %s", oldPath, serviceFilePath)
		logger.Warn("If you customized this file, please run 'systemctl edit viam-agent' and create overrides there")
		if err := os.RemoveAll(oldPath); err != nil {
			logger.Error(errw.Wrapf(err, "removing old service file %s, please delete manually", oldPath))
		}
	}

	logger.Infof("enabling systemd viam-agent service")
	cmd = exec.Command("systemctl", "daemon-reload")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return errw.Wrapf(err, "running 'systemctl daemon-reload' output: %s", output)
	}

	cmd = exec.Command("systemctl", "enable", "viam-agent")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return errw.Wrapf(err, "running 'systemctl enable viam-agent' output: %s", output)
	}

	_, err = os.Stat("/etc/viam.json")
	if err != nil {
		if errw.Is(err, fs.ErrNotExist) {
			logger.Warn("No config file found at /etc/viam.json, please install one before running viam-agent service.")
		} else {
			return errw.Wrap(err, "reading /etc/viam.json")
		}
	}

	logger.Info("Install complete. Please (re)start the service with 'systemctl restart viam-agent' when ready.")

	return errors.Join(agent.SyncFS("/etc"), agent.SyncFS(serviceFilePath), agent.SyncFS(agent.ViamDirs["viam"]))
}

func inSystemdPath(path string, logger *zap.SugaredLogger) bool {
	cmd := exec.Command("systemd-path", "systemd-search-system-unit")
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error(errw.Wrapf(err, "running 'systemd-path systemd-search-system-unit' output: %s", output))
		return false
	}
	searchPaths := strings.Split(strings.TrimSpace(string(output)), ":")
	for _, searchPath := range searchPaths {
		if searchPath == path {
			return true
		}
	}
	return false
}

func getServiceFilePath(logger *zap.SugaredLogger) (string, bool, error) {
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
