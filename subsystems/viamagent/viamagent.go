package viamagent

import (
	"context"
	_ "embed"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/pkg/errors"
	"github.com/viamrobotics/agent"
	"github.com/viamrobotics/agent/subsystems"
	"github.com/viamrobotics/agent/subsystems/registry"
	"go.uber.org/zap"
	pb "go.viam.com/api/app/agent/v1"
)

func init() {
	registry.Register(subsysName, NewSubsystem)
}

const (
	subsysName      = "viam-agent"
	serviceFileDir  = "/etc/systemd/system"
	serviceFilePath = "/etc/systemd/system/viam-agent.service"
)

var (
	// versions embedded at build time.
	Version     = ""
	GitRevision = ""

	//go:embed viam-agent.service
	serviceFileContents []byte
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
func (a *agentSubsystem) Update(ctx context.Context, cfg *pb.DeviceSubsystemConfig) (bool, error) {
	expectedPath := filepath.Join(agent.ViamDirs["bin"], subsysName)

	// Run the newly updated version to install systemd and other service files.
	cmd := exec.Command(expectedPath, "--install")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false, errors.Wrapf(err, "error running post install step %s", output)
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

// GetVersion returns the version embedded at build time.
func GetRevision() string {
	if GitRevision == "" {
		return "unknown"
	}
	return GitRevision
}

func Install() error {
	// Create/check required folder structure exists.
	if err := initPaths(); err != nil {
		return err
	}

	// Check for systemd
	_, err := os.Stat(serviceFileDir)
	if errors.Is(err, fs.ErrNotExist) {
		return errors.Wrapf(err, "can only install on systems using systemd, but %s is missing", serviceFileDir)
	}
	if err != nil {
		return errors.Wrapf(err, "error getting info for %s", serviceFileDir)
	}

	// If this is a brand new install, we want to copy ourselves into place temporarily.
	expectedPath := filepath.Join(agent.ViamDirs["bin"], subsysName)
	_, err = os.Stat(expectedPath)
	if errors.Is(err, fs.ErrNotExist) {
		curPath, err := os.Executable()
		if err != nil {
			return errors.Wrap(err, "cannot get path to self")
		}
		if err := os.Rename(curPath, expectedPath); err != nil {
			return errors.Wrapf(err, "cannot install binary to %s", expectedPath)
		}

		if err := os.Chmod(expectedPath, 0o755); err != nil {
			return errors.Wrapf(err, "cannot set permissiosn on %s", expectedPath)
		}
	}

	if err := os.WriteFile(serviceFilePath, serviceFileContents, 0o644); err != nil {
		return errors.Wrapf(err, "unable to write systemd service file %s", serviceFilePath)
	}

	cmd := exec.Command("systemctl", "daemon-reload")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "problem running 'systemctl daemon-reload' output: %s", output)
	}

	cmd = exec.Command("systemctl", "enable", "viam-agent")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "problem running 'systemctl enable viam-agent' output: %s", output)
	}

	_, err = os.Stat("/etc/viam.json")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			fmt.Println("No config file found at /etc/viam.json, please install one before running viam-agent service.")
		}else{
			return errors.Wrap(err, "error reading /etc/viam.json")
		}
	}

	fmt.Println("Install complete. Please (re)start the service with 'systemctl restart viam-agent' when ready.")

	return nil
}

func initPaths() error {
	uid := os.Getuid()
	for _, p := range agent.ViamDirs {
		info, err := os.Stat(p)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				if err := os.MkdirAll(p, 0o755); err != nil {
					return err
				}
				continue
			}
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			// should be impossible on Linux
			return errors.New("cannot convert to syscall.Stat_t")
		}
		if uid != int(stat.Uid) {
			return errors.Errorf("%s is owned by UID %d but the current UID is %d", p, stat.Uid, uid)
		}
		if !info.IsDir() {
			return errors.Errorf("%s should be a directory, but is not", p)
		}
		if info.Mode().Perm() != 0o755 {
			return errors.Errorf("%s should be have permission set to 0755, but has permissions %d", p, info.Mode().Perm())
		}
	}
	return nil
}
