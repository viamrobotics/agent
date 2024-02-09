// Package provisioning contains the provisioning agent subsystem.
package provisioning

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"regexp"
	"sync"
	"syscall"
	"time"

	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent"
	"github.com/viamrobotics/agent/subsystems"
	"github.com/viamrobotics/agent/subsystems/registry"
	"go.uber.org/zap"
	pb "go.viam.com/api/app/agent/v1"
)

func init() {
	registry.Register(SubsysName, NewSubsystem, DefaultConfig)
}

var (
	Debug         = false
	DefaultConfig = &pb.DeviceSubsystemConfig{}
)

const (
	startTimeout = time.Minute
	stopTimeout  = time.Minute
	SubsysName   = "agent-provisioning"
)

var (
	ConfigFilePath             = path.Join(agent.ViamDirs["etc"], SubsysName+".json")
	AppConfigFilePath          = "/etc/viam.json"
	ProvisioningConfigFilePath = "/etc/viam-provisioning.json"
)

type provisioning struct {
	mu        sync.Mutex
	cmd       *exec.Cmd
	running   bool
	shouldRun bool
	lastExit  int
	exitChan  chan struct{}

	// for blocking start/stop/check ops while another is in progress
	startStopMu sync.Mutex

	logger *zap.SugaredLogger
}

func (n *provisioning) Start(ctx context.Context) error {
	n.startStopMu.Lock()
	defer n.startStopMu.Unlock()

	n.mu.Lock()

	if n.running {
		n.mu.Unlock()
		return nil
	}
	if n.shouldRun {
		n.logger.Warnf("Restarting %s after unexpected exit", SubsysName)
	} else {
		n.logger.Infof("Starting %s", SubsysName)
		n.shouldRun = true
	}

	stdio := agent.NewMatchingLogger(n.logger, false)
	stderr := agent.NewMatchingLogger(n.logger, true)

	cmdArgs := []string{"--config", ConfigFilePath, "--app-config", AppConfigFilePath, "--provisioning-config", ProvisioningConfigFilePath}
	if Debug {
		cmdArgs = append(cmdArgs, "--debug")
	}
	//nolint:gosec
	n.cmd = exec.Command(path.Join(agent.ViamDirs["bin"], SubsysName), cmdArgs...)
	n.cmd.Dir = agent.ViamDirs["viam"]
	n.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	n.cmd.Stdout = stdio
	n.cmd.Stderr = stderr

	// watch for this line in the logs to indicate successful startup
	c, err := stdio.AddMatcher("checkStartup", regexp.MustCompile(`agent-provisioning startup complete`), false)
	if err != nil {
		n.mu.Unlock()
		return err
	}
	defer stdio.DeleteMatcher("checkStartup")

	err = n.cmd.Start()
	if err != nil {
		n.mu.Unlock()
		return errw.Wrapf(err, "error starting %s", SubsysName)
	}
	n.running = true
	n.exitChan = make(chan struct{})

	// must be unlocked before spawning goroutine
	n.mu.Unlock()
	go func() {
		err := n.cmd.Wait()
		n.mu.Lock()
		defer n.mu.Unlock()
		n.running = false
		n.logger.Infof("%s exited", SubsysName)
		if err != nil {
			n.logger.Errorw("error while getting process status", "error", err)
		}
		if n.cmd.ProcessState != nil {
			n.lastExit = n.cmd.ProcessState.ExitCode()
			if n.lastExit != 0 {
				n.logger.Errorw("non-zero exit code", "exit code", n.lastExit)
			}
		}
		close(n.exitChan)
	}()

	select {
	case <-c:
		n.logger.Infof("%s started", SubsysName)
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(startTimeout):
		return errw.New("startup timed out")
	case <-n.exitChan:
		return errw.New("startup failed")
	}
}

func (n *provisioning) Stop(ctx context.Context) error {
	n.startStopMu.Lock()
	defer n.startStopMu.Unlock()

	n.mu.Lock()
	running := n.running
	n.shouldRun = false
	n.mu.Unlock()

	if !running {
		return nil
	}

	// interrupt early in startup
	if n.cmd == nil {
		return nil
	}

	n.logger.Infof("Stopping %s", SubsysName)

	err := n.cmd.Process.Signal(syscall.SIGTERM)
	if err != nil {
		n.logger.Error(err)
	}

	if n.waitForExit(ctx, stopTimeout/2) {
		n.logger.Infof("%s successfully stopped", SubsysName)
		return nil
	}

	n.logger.Warnf("%s refused to exit, killing", SubsysName)
	err = syscall.Kill(-n.cmd.Process.Pid, syscall.SIGKILL)
	if err != nil {
		n.logger.Error(err)
	}

	if n.waitForExit(ctx, stopTimeout/2) {
		n.logger.Infof("%s successfully killed", SubsysName)
		return nil
	}

	return errw.Errorf("%s process couldn't be killed", SubsysName)
}

func (n *provisioning) waitForExit(ctx context.Context, timeout time.Duration) bool {
	n.mu.Lock()
	exitChan := n.exitChan
	running := n.running
	n.mu.Unlock()

	if !running {
		return true
	}

	select {
	case <-exitChan:
		return true
	case <-ctx.Done():
		return false
	case <-time.After(timeout):
		return false
	}
}

// Healthcheck sends a USR1 signal to the provisioning process, which should cause it to log "HEALTHY" to stdout.
func (n *provisioning) HealthCheck(ctx context.Context) (errRet error) {
	n.startStopMu.Lock()
	defer n.startStopMu.Unlock()
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.running {
		return errw.Errorf("%s not running", SubsysName)
	}

	n.logger.Debugf("starting healthcheck for %s", SubsysName)

	checkChan, err := n.cmd.Stdout.(*agent.MatchingLogger).AddMatcher("healthcheck", regexp.MustCompile(`HEALTHY`), true)
	if err != nil {
		return err
	}
	defer func() {
		matcher, ok := n.cmd.Stdout.(*agent.MatchingLogger)
		if ok {
			matcher.DeleteMatcher("healthcheck")
		}
	}()

	err = n.cmd.Process.Signal(syscall.SIGUSR1)
	if err != nil {
		n.logger.Error(err)
	}

	select {
	case <-time.After(time.Second * 30):
	case <-ctx.Done():
	case <-checkChan:
		n.logger.Debugf("healthcheck for %s is good", SubsysName)
		return nil
	}
	return errw.Errorf("timeout waiting for healthcheck on %s", SubsysName)
}

func (n *provisioning) Update(ctx context.Context, cfg *pb.DeviceSubsystemConfig, newVersion bool) (bool, error) {
	jsonBytes, err := cfg.GetAttributes().MarshalJSON()
	if err != nil {
		return true, err
	}
	//nolint:gosec
	fileBytes, err := os.ReadFile(ConfigFilePath)
	// If no changes, only restart if there was a new version.
	if err == nil && bytes.Equal(fileBytes, jsonBytes) {
		return newVersion, nil
	}

	// If an error reading the config file, restart and return the error
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return true, err
	}

	// If attribute changes, restart after writing the new config file.
	//nolint:gosec
	return true, os.WriteFile(ConfigFilePath, jsonBytes, 0o644)
}

func NewSubsystem(ctx context.Context, logger *zap.SugaredLogger, updateConf *pb.DeviceSubsystemConfig) (subsystems.Subsystem, error) {
	return agent.NewAgentSubsystem(ctx, SubsysName, logger, &provisioning{logger: logger.Named(SubsysName)})
}
