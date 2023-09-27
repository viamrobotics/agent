// Package viamserver contains the viam-server agent subsystem.
package viamserver

import (
	"context"
	"net/http"
	"os/exec"
	"path"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/viamrobotics/agent"
	"go.uber.org/zap"
)

const startStopTimeout = time.Second * 30

type viamServer struct {
	mu       sync.Mutex
	cmd      *exec.Cmd
	running  bool
	lastExit int
	checkURL string

	logger    *zap.SugaredLogger
	bgWorkers sync.WaitGroup
}

func (s *viamServer) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return nil
	}
	s.logger.Info("SMURF START")

	stdio := &MatchingLogger{logger: s.logger}
	stderr := &MatchingLogger{logger: s.logger, defaultError: true}

	s.cmd = exec.Command(path.Join(agent.ViamDirs["bin"], "viam-server"), "-config", path.Join(agent.ViamDirs["etc"], "viam.json"))
	s.cmd.Dir = agent.ViamDirs["viam"]
	s.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	s.cmd.Stdout = stdio
	s.cmd.Stderr = stderr

	// watch for this line in the logs to indicate successful startup
	c, err := stdio.AddMatcher("checkURL", regexp.MustCompile(`serving\W*{"url": "(https?://[\w\.:-]+)".*}`))
	if err != nil {
		return err
	}
	defer stdio.DeleteMatcher("checkURL")

	err = s.cmd.Start()
	if err != nil {
		return errors.Wrap(err, "error starting viam-server")
	}

	s.bgWorkers.Add(1)
	go func() {
		defer s.bgWorkers.Done()
		err := s.cmd.Wait()
		s.mu.Lock()
		defer s.mu.Unlock()
		s.running = false
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

	ctxTimeout, cancelFunc := context.WithTimeout(ctx, startStopTimeout)
	defer cancelFunc()

	select {
	case matches := <-c:
		s.checkURL = matches[1]
		s.logger.Infof("healthcheck URL: %s", s.checkURL)
	case <-ctxTimeout.Done():
		s.logger.Error("startup timed out")
		// we'll let the health check handle restarting if this is a failure
	}
	s.logger.Info("SMURF STARTED")
	s.running = true
	return nil
}

func (s *viamServer) Stop(ctx context.Context) error {
	s.logger.Info("SMURF STOP")
	s.mu.Lock()
	running := s.running
	s.mu.Unlock()

	if !running {
		return nil
	}

	err := s.cmd.Process.Signal(syscall.SIGTERM)
	if err != nil {
		s.logger.Error(err)
	}

	ctxTimeout, cancelFunc1 := context.WithTimeout(ctx, startStopTimeout)
	defer cancelFunc1()
	if s.waitForExit(ctxTimeout, startStopTimeout) {
		s.logger.Warn("SMURF Done 1")
		return nil
	}

	err = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
	if err != nil {
		s.logger.Error(err)
	}

	if s.waitForExit(ctxTimeout, startStopTimeout) {
		s.logger.Warn("SMURF Done 2")
		return nil
	}

	return errors.New("viam-server process couldn't be killed")
}

func (s *viamServer) waitForExit(ctx context.Context, timeout time.Duration) bool {
	ctxTimeout, cancelFunc := context.WithTimeout(ctx, startStopTimeout)
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

func (s *viamServer) HealthCheck(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return errors.New("viam-server not running")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.checkURL, nil)
	if err != nil {
		return errors.Wrap(err, "checking viam-server status")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return errors.Wrap(err, "checking viam-server status")
	}
	s.logger.Infof("SMURF Status Check: %d", resp.StatusCode)
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return errors.Wrapf(err, "checking viam-server status, got code: %d", resp.StatusCode)
	}

	return nil
}

func NewSubsystem(ctx context.Context, updateConf agent.SubsystemConfig, logger *zap.SugaredLogger) *viamServer {
	return &viamServer{
		checkURL: "http://127.0.0.1:8080",
		logger:   logger.Named("viam-server"),
	}
}
