// Package networking contains the networking agent subsystem.
package networking

import (
	"bytes"
	"context"
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
	registry.Register(subsysName, NewSubsystem)
}

const (
	startTimeout = time.Minute
	stopTimeout  = time.Minute
	subsysName   = "agent-networking"

	provisioningConfigPath = "/etc/viam-provisioning.json"
)

var ConfigFilePath = path.Join(agent.ViamDirs["etc"], subsysName + ".json")


type networking struct {
	mu        sync.Mutex
	cmd       *exec.Cmd
	running   bool
	shouldRun bool
	lastExit  int
	healthy   bool

	// for blocking start/stop/check ops while another is in progress
	startStopMu sync.Mutex

	logger *zap.SugaredLogger
}

func (n *networking) Start(ctx context.Context) error {
	n.startStopMu.Lock()
	defer n.startStopMu.Unlock()

	n.mu.Lock()
	defer n.mu.Unlock()

	if n.running {
		return nil
	}
	if n.shouldRun {
		n.logger.Warnf("Restarting %s after unexpected exit", subsysName)
	} else {
		n.logger.Infof("Starting %s", subsysName)
		n.shouldRun = true
	}

	stdio := agent.NewMatchingLogger(n.logger, false)
	stderr := agent.NewMatchingLogger(n.logger, true)

	n.cmd = exec.Command(path.Join(agent.ViamDirs["bin"], subsysName), "-config", ConfigFilePath)
	n.cmd.Dir = agent.ViamDirs["viam"]
	n.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	n.cmd.Stdout = stdio
	n.cmd.Stderr = stderr

	// watch for this line in the logs to indicate successful startup
	// SMURF TODO fix this to corrrect output
	c, err := stdio.AddMatcher("checkStartup", regexp.MustCompile(`networking subsystem started`), false)
	if err != nil {
		return err
	}
	defer stdio.DeleteMatcher("checkStartup")

	err = n.cmd.Start()
	if err != nil {
		return errw.Wrapf(err, "error starting %s", subsysName)
	}
	n.running = true

	go func() {
		err := n.cmd.Wait()
		n.mu.Lock()
		defer n.mu.Unlock()
		n.running = false
		n.logger.Infof("%s exited", subsysName)
		if err != nil {
			n.logger.Errorw("error while getting process status", "error", err)
		}
		if n.cmd.ProcessState != nil {
			n.lastExit = n.cmd.ProcessState.ExitCode()
			if n.lastExit != 0 {
				n.logger.Errorw("non-zero exit code", "exit code", n.lastExit)
			}
		}
	}()

	select {
	case <-c:
		n.logger.Infof("%s started", subsysName)
		return nil
	case <-ctx.Done():
	case <-time.After(time.Second * 30):
	}
	// we'll let the health check handle restarting if this is a failure
	n.logger.Error("startup timed out")
	return nil
}

func (n *networking) Stop(ctx context.Context) error {
	n.logger.Infof("Stopping %s", subsysName)
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

	err := n.cmd.Process.Signal(syscall.SIGTERM)
	if err != nil {
		n.logger.Error(err)
	}

	if n.waitForExit(ctx, stopTimeout/2) {
		n.logger.Infof("%s successfully stopped", subsysName)
		return nil
	}

	n.logger.Warnf("%s refused to exit, killing", subsysName)
	err = syscall.Kill(-n.cmd.Process.Pid, syscall.SIGKILL)
	if err != nil {
		n.logger.Error(err)
	}

	if n.waitForExit(ctx, stopTimeout/2) {
		n.logger.Infof("%s successfully killed", subsysName)
		return nil
	}

	return errw.Errorf("%s process couldn't be killed", subsysName)
}

func (n *networking) waitForExit(ctx context.Context, timeout time.Duration) bool {
	ctxTimeout, cancelFunc := context.WithTimeout(ctx, timeout)
	defer cancelFunc()

	// loop so that even after the context expires, we still have one more second before a final check.
	var lastTry bool
	for {
		n.mu.Lock()
		running := n.running
		n.mu.Unlock()
		if !running || lastTry {
			return !running
		}
		if ctxTimeout.Err() != nil {
			lastTry = true
		}
		time.Sleep(time.Second)
	}
}

// Healthcheck sends a USR1 signal to the networking process, which should cause it to log "HEALTHY" to stdout.
func (n *networking) HealthCheck(ctx context.Context) (errRet error) {
	n.startStopMu.Lock()
	defer n.startStopMu.Unlock()
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.running {
		return errw.Errorf("%s not running", subsysName)
	}

	n.logger.Debugf("starting healthcheck for %s", subsysName)

	checkChan, err := n.cmd.Stdout.(*agent.MatchingLogger).AddMatcher("healthcheck",  regexp.MustCompile(`HEALTHY`), true)
	if err != nil {
		return err
	}
	defer n.cmd.Stdout.(*agent.MatchingLogger).DeleteMatcher("healthcheck")

	err = n.cmd.Process.Signal(syscall.SIGUSR1)
	if err != nil {
		n.logger.Error(err)
	}

	select {
	case <-time.After(time.Second * 30):
	case <-ctx.Done():
	case <-checkChan:
		n.logger.Debugf("healthcheck for %s is good", subsysName)
		return nil
	}
	return errw.Errorf("timeout waiting for healthcheck on %s", subsysName)

}

func (n *networking) Update(ctx context.Context, cfg *pb.DeviceSubsystemConfig, newVersion bool) (bool, error) {
	fileBytes, err := os.ReadFile(ConfigFilePath)
	if err != nil {
		return true, err
	}

	jsonBytes, err := cfg.Attributes.MarshalJSON()
	if err != nil {
		return true, err
	}

	// If no changes, only restart if there was a new version.
	if bytes.Equal(fileBytes, jsonBytes){
		return newVersion, nil 
	}

	// If attribute changes, restart after writing the new config file.
	return true, os.WriteFile(ConfigFilePath, jsonBytes, 0644)
}

func NewSubsystem(ctx context.Context, logger *zap.SugaredLogger, updateConf *pb.DeviceSubsystemConfig) (subsystems.Subsystem, error) {
	return agent.NewAgentSubsystem(ctx, subsysName, logger, &networking{logger: logger.Named(subsysName)})
}
