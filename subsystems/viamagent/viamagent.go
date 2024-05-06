// Package viamagent is the subsystem for the viam-agent itself. It contains code to install/update the systemd service as well.
package viamagent

import (
	"context"
	_ "embed"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/pkg/errors"
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
	serviceFileName = "viam-agent.service"
)

var (
	// versions embedded at build time.
	Version     = ""
	GitRevision = ""

	//go:embed viam-agent.service
	serviceFileContents []byte
	DefaultConfig       = &pb.DeviceSubsystemConfig{}

	serviceFilePath = filepath.Join(serviceFileDir, serviceFileName)
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
		return false, errors.Wrapf(err, "running post install step %s", output)
	}

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
	cmd := exec.Command("systemctl", "whoami")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "can only install on systems using systemd, but 'systemctl whoami' returned errors %s", output)
	}

	// Create/check required folder structure exists.
	if err := agent.InitPaths(); err != nil {
		return err
	}
	//nolint:gosec
	if err := os.MkdirAll(serviceFileDir, 0o755); err != nil {
		return errors.Wrapf(err, "creating directory %s", serviceFileDir)
	}

	// If this is a brand new install, we want to symlink ourselves into place temporarily.
	expectedPath := filepath.Join(agent.ViamDirs["bin"], subsysName)
	curPath, err := os.Executable()
	if err != nil {
		return errors.Wrap(err, "getting path to self")
	}

	isSelf, err := agent.CheckIfSame(curPath, expectedPath)
	if err != nil {
		return errors.Wrap(err, "checking if installed viam-agent is myself")
	}

	if !isSelf {
		logger.Infof("adding a symlink to %s at %s", curPath, expectedPath)
		if err := os.Remove(expectedPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return errors.Wrapf(err, "removing symlink/file at %s", expectedPath)
		}
		if err := os.Symlink(curPath, expectedPath); err != nil {
			return errors.Wrapf(err, "installing symlink at %s", expectedPath)
		}
	}

	// one-time, remove old /etc based service file when moving to new proper local location
	removeOldServiceFile(logger)

	logger.Infof("writing systemd service file to %s", serviceFilePath)
	//nolint:gosec
	if err := os.WriteFile(serviceFilePath, serviceFileContents, 0o644); err != nil {
		return errors.Wrapf(err, "writing systemd service file %s", serviceFilePath)
	}

	logger.Infof("enabling systemd viam-agent service")
	cmd = exec.Command("systemctl", "daemon-reload")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "running 'systemctl daemon-reload' output: %s", output)
	}

	cmd = exec.Command("systemctl", "enable", "viam-agent")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "running 'systemctl enable viam-agent' output: %s", output)
	}

	_, err = os.Stat("/etc/viam.json")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			//nolint:forbidigo
			fmt.Println("No config file found at /etc/viam.json, please install one before running viam-agent service.")
		} else {
			return errors.Wrap(err, "reading /etc/viam.json")
		}
	}
	//nolint:forbidigo
	fmt.Println("Install complete. Please (re)start the service with 'systemctl restart viam-agent' when ready.")

	return agent.SyncFS("/etc")
}

func removeOldServiceFile(logger *zap.SugaredLogger) {
	oldPath := "/etc/systemd/system/viam-agent.service"
	_, oldErr := os.Stat(oldPath)
	_, newErr := os.Stat(serviceFilePath)
	if oldErr == nil && errors.Is(newErr, fs.ErrNotExist) {
		logger.Warn("Removing system service file %s in favor of vendor file at %s", oldPath, serviceFilePath)
		logger.Warn("If you customized this file, please run 'systemctl edit viam-agent' and create overrides there")
		if err := os.RemoveAll(oldPath); err != nil {
			logger.Error(errors.Wrapf(err, "removing old service file %s, please delete manually", oldPath))
		}
	}
}
