// Package viamserver contains the viam-server agent subsystem.
package viamserver

import (
	"context"
	"errors"
	"net/http"
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
	startTimeout = time.Minute * 5
	stopTimeout  = time.Minute * 2
	subsysName   = "viam-server"
)

var ConfigFilePath = "/etc/viam.json"

type viamServer struct {
	mu        sync.Mutex
	cmd       *exec.Cmd
	running   bool
	shouldRun bool
	lastExit  int
	checkURL  string

	logger    *zap.SugaredLogger
	bgWorkers sync.WaitGroup
}

func (s *viamServer) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return nil
	}
	if s.shouldRun {
		s.logger.Warn("Restarting viam-server after unexpected exit")
	} else {
		s.logger.Info("Starting viam-server")
		s.shouldRun = true
	}

	stdio := &MatchingLogger{logger: s.logger}
	stderr := &MatchingLogger{logger: s.logger, defaultError: true}

	s.cmd = exec.Command(path.Join(agent.ViamDirs["bin"], subsysName), "-config", ConfigFilePath)
	s.cmd.Dir = agent.ViamDirs["viam"]
	s.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	s.cmd.Stdout = stdio
	s.cmd.Stderr = stderr

	// watch for this line in the logs to indicate successful startup
	c, err := stdio.AddMatcher("checkURL", regexp.MustCompile(`serving\W*{"url":\W*"(https?://[\w\.:-]+)".*}`))
	if err != nil {
		return err
	}
	defer stdio.DeleteMatcher("checkURL")

	err = s.cmd.Start()
	if err != nil {
		return errw.Wrapf(err, "error starting %s", subsysName)
	}

	s.bgWorkers.Add(1)
	go func() {
		defer s.bgWorkers.Done()
		err := s.cmd.Wait()
		s.mu.Lock()
		defer s.mu.Unlock()
		s.running = false
		s.logger.Info("viam-server exited")
		if err != nil {
			s.logger.Errorw("error while getting process status", "error", err)
		}
		if s.cmd.ProcessState != nil {
			s.lastExit = s.cmd.ProcessState.ExitCode()
			if s.lastExit != 0 {
				s.logger.Errorw("non-zero exit code", "exit code", s.lastExit)
			}
		}
	}()

	ctxTimeout, cancelFunc := context.WithTimeout(ctx, startTimeout)
	defer cancelFunc()

	select {
	case matches := <-c:
		s.checkURL = matches[1]
		s.logger.Infof("healthcheck URL: %s", s.checkURL)
	case <-ctxTimeout.Done():
		s.logger.Error("startup timed out")
		// we'll let the health check handle restarting if this is a failure
	}
	s.logger.Infof("%s successfully started", subsysName)
	s.running = true
	return nil
}

func (s *viamServer) Stop(ctx context.Context) error {
	s.logger.Info("Stopping viam-server")
	s.mu.Lock()
	running := s.running
	s.shouldRun = false
	s.mu.Unlock()

	if !running {
		return nil
	}

	err := s.cmd.Process.Signal(syscall.SIGTERM)
	if err != nil {
		s.logger.Error(err)
	}

	if s.waitForExit(ctx, stopTimeout/2) {
		return nil
	}

	err = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
	if err != nil {
		s.logger.Error(err)
	}

	if s.waitForExit(ctx, stopTimeout/2) {
		s.logger.Info("viam-agent successfully stopped")
		return nil
	}

	return errw.Errorf("%s process couldn't be killed", subsysName)
}

func (s *viamServer) waitForExit(ctx context.Context, timeout time.Duration) bool {
	ctxTimeout, cancelFunc := context.WithTimeout(ctx, timeout)
	defer cancelFunc()
	timer := time.NewTicker(time.Second)
	defer timer.Stop()

	for {
		s.mu.Lock()
		running := s.running
		s.mu.Unlock()
		if !running {
			return true
		}
		if ctxTimeout.Err() != nil {
			return false
		}
		select {
		case <-ctxTimeout.Done():
			return false
		case <-timer.C:
		}
	}
}

func (s *viamServer) HealthCheck(ctx context.Context) (errRet error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return errw.Errorf("%s not running", subsysName)
	}
	if s.checkURL == "" {
		return errw.Errorf("can't find listening URL for %s", subsysName)
	}

	timeoutCtx, cancelFunc := context.WithTimeout(ctx, time.Second*30)
	defer cancelFunc()

	req, err := http.NewRequestWithContext(timeoutCtx, http.MethodGet, s.checkURL, nil)
	if err != nil {
		return errw.Wrapf(err, "checking %s status", subsysName)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errw.Wrapf(err, "checking %s status", subsysName)
	}
	defer func() {
		errRet = errors.Join(errRet, resp.Body.Close())
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errw.Wrapf(err, "checking %s status, got code: %d", subsysName, resp.StatusCode)
	}

	return errRet
}

func NewSubsystem(ctx context.Context, logger *zap.SugaredLogger, updateConf *pb.DeviceSubsystemConfig) (subsystems.Subsystem, error) {
	return agent.NewAgentSubsystem(ctx, subsysName, logger, &viamServer{logger: logger.Named(subsysName)})
}
