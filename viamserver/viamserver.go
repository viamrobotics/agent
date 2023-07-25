// Package viamserver contains the viam-server agent subsystem.
package viamserver

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"os"
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

	stdio := &stdioLogger{logger: s.logger}
	stderr := &stderrLogger{logger: s.logger}

	s.cmd = exec.Command(path.Join("bin", "viam-server"), "-config", path.Join("etc", "viam.json"))
	s.cmd.Dir = agent.ViamDir
	s.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	s.cmd.Stdout = stdio
	s.cmd.Stderr = stderr

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

func (s *viamServer) Update(ctx context.Context, cfg agent.SubsystemConfig) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	shasum, err := agent.GetFileSum(path.Join(agent.ViamDir, "bin", cfg.Filename))
	if err == nil && bytes.Equal(shasum, cfg.SHA256) {
		return false, nil
	}

	tempfile, err := agent.DownloadFile(ctx, cfg.URL)
	if err != nil {
		return false, errors.Wrap(err, "downloading viam-server subsystem")
	}
	defer func() {
		err := os.Remove(tempfile)
		if err != nil && !os.IsNotExist(err) {
			s.logger.Error(err)
		}
	}()

	extractedfile := tempfile
	if cfg.Format == agent.FormatXZ || cfg.Format == agent.FormatXZExecutable {
		extractedfile, err = agent.DecompressFile(tempfile)
		if err != nil {
			return false, errors.Wrap(err, "decompressing viam-server subsystem")
		}
		defer func() {
			err := os.Remove(extractedfile)
			if err != nil && !os.IsNotExist(err) {
				s.logger.Error(err)
			}
		}()
	}

	shasum, err = agent.GetFileSum(path.Join(agent.ViamDir, "bin", cfg.Filename))
	if err != nil {
		return false, errors.Wrap(err, "getting file shasum")
	}
	if !bytes.Equal(shasum, cfg.SHA256) {
		return false, fmt.Errorf("sha256 of downloaded file (%x) does not match config (%x)", shasum, cfg.SHA256)
	}

	if cfg.Format == agent.FormatExecutable || cfg.Format == agent.FormatXZExecutable {
		if err := os.Chmod(extractedfile, 0o755); err != nil {
			return false, err
		}
	} else {
		if err := os.Chmod(extractedfile, 0o644); err != nil {
			return false, err
		}
	}

	os.MkdirAll(path.Join(agent.ViamDir, "bin"), 0o755)
	os.Rename(tempfile, path.Join(agent.ViamDir, "bin", cfg.Filename))

	return true, nil
}

func NewSubsystem(ctx context.Context, updateConf agent.SubsystemConfig, logger *zap.SugaredLogger) *viamServer {
	return &viamServer{
		checkURL: "http://127.0.0.1:8080",
		logger:   logger.Named("viam-server"),
	}
}

type matcher struct {
	regex   *regexp.Regexp
	channel chan ([]string)
}

type stdioLogger struct {
	mu       sync.RWMutex
	logger   *zap.SugaredLogger
	matchers map[string]matcher
}

func (l *stdioLogger) AddMatcher(name string, regex *regexp.Regexp) (<-chan []string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.matchers == nil {
		l.matchers = make(map[string]matcher)
	}
	_, ok := l.matchers[name]
	if ok {
		return nil, errors.Errorf("matcher already exists: %s", name)
	}
	c := make(chan []string, 32)
	l.matchers[name] = matcher{regex: regex, channel: c}
	return c, nil
}

func (l *stdioLogger) DeleteMatcher(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	m, ok := l.matchers[name]
	if ok {
		close(m.channel)
		delete(l.matchers, name)
	}
}

func (l *stdioLogger) Write(p []byte) (int, error) {
	line := string(p)
	l.logger.Info(line)
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, m := range l.matchers {
		matches := m.regex.FindStringSubmatch(line)
		if matches != nil {
			m.channel <- matches
		}
	}
	return len(p), nil
}

type stderrLogger struct {
	logger *zap.SugaredLogger
}

func (l *stderrLogger) Write(p []byte) (int, error) {
	l.logger.Error(string(p))
	return len(p), nil
}
