// Package viamserver contains the viam-server agent subsystem.
package viamserver

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/subsystems"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
)

const (
	// stopTermTimeout must be higher than viam-server shutdown timeout of 90 secs.
	stopTermTimeout = time.Minute * 2
	stopKillTimeout = time.Second * 10
	SubsysName      = "viam-server"
)

type viamServer struct {
	mu           sync.Mutex
	cmd          *exec.Cmd
	running      bool
	shouldRun    bool
	lastExit     int
	exitChan     chan struct{}
	startTimeout time.Duration
	checkURL     string
	checkURLAlt  string

	// extra environment variables to set before launching server
	extraEnvVars map[string]string

	// for blocking start/stop/check ops while another is in progress
	startStopMu sync.Mutex

	// whether this viamserver instance handles needs restart checking itself; calculated
	// and cached at startup; used by the manager to determine whether agent should handle
	// needs restart checking on viamserver's behalf (this is the case for new viamserver
	// versions)
	doesNotHandleNeedsRestart bool

	logger logging.Logger
}

// Returns true if path is definitely missing,
// false if file is present or something else is wrong.
func pathMissing(path string) bool {
	_, err := os.Stat(path)
	return errors.Is(err, os.ErrNotExist)
}

func (s *viamServer) Start(ctx context.Context) error {
	s.startStopMu.Lock()
	defer s.startStopMu.Unlock()

	s.mu.Lock()

	if s.running {
		s.mu.Unlock()
		return nil
	}
	binPath := path.Join(utils.ViamDirs.Bin, SubsysName)

	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}
	if pathMissing(binPath) {
		s.logger.Warnf("viam-server binary missing at %s, not starting", binPath)
		// todo: nested func so unlock is deferable
		s.mu.Unlock()
		return nil
	}
	if s.shouldRun {
		s.logger.Warnf("Restarting %s after unexpected exit", SubsysName)
	} else {
		s.logger.Infof("Starting %s", SubsysName)
		s.shouldRun = true
	}

	stdio := utils.NewMatchingLogger(s.logger, false, false, "viam-server.StdOut")
	stderr := utils.NewMatchingLogger(s.logger, false, false, "viam-server.StdErr")
	//nolint:gosec
	s.cmd = exec.Command(binPath, "-config", utils.AppConfigFilePath)
	s.cmd.Dir = utils.ViamDirs.Viam
	utils.PlatformProcSettings(s.cmd)
	s.cmd.Stdout = stdio
	s.cmd.Stderr = stderr

	if len(s.extraEnvVars) > 0 {
		s.logger.Infow("Adding environment variables from config to viam-server startup", "extraEnvVars", s.extraEnvVars)

		// if s.cmd.Env is not explicitly specified (nil), viam-server would inherit all env vars in Agent's environment
		s.cmd.Env = s.cmd.Environ()
		for k, v := range s.extraEnvVars {
			s.cmd.Env = append(s.cmd.Env, k+"="+v)
		}
		s.logger.Debugw("Starting viam-server with environment variables", "cmd.Env", s.cmd.Env)
	}

	// watch for this line in the logs to indicate successful startup
	c, err := stdio.AddMatcher(
		"checkURL",
		regexp.MustCompile(`serving\W*{"url":\W*"(https?://[\w\.:-]+)".*"alt_url":\W*"(https?://[\w\.:-]+)"}`),
		false,
	)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	defer stdio.DeleteMatcher("checkURL")

	err = s.cmd.Start()
	if err != nil {
		s.mu.Unlock()
		return errw.Wrapf(err, "starting %s", SubsysName)
	}
	s.running = true
	s.exitChan = make(chan struct{})

	// must be unlocked before spawning goroutine
	s.mu.Unlock()
	go func() {
		defer utils.Recover(s.logger, func(_ any) {
			if err := s.Stop(ctx); err != nil {
				s.logger.Error(err)
			}
		})
		err := s.cmd.Wait()
		s.mu.Lock()
		defer s.mu.Unlock()
		s.running = false
		s.logger.Infof("%s exited", SubsysName)
		if err != nil {
			s.logger.Error(errw.Wrap(err, "error while getting process status"))
		}
		if s.cmd.ProcessState != nil {
			s.lastExit = s.cmd.ProcessState.ExitCode()
			if s.lastExit != 0 {
				s.logger.Errorf("non-zero exit code: %d", s.lastExit)
			}
		}
		if s.shouldRun {
			s.logger.Infof("%s exited unexpectedly and will be restarted shortly", SubsysName)
		}
		close(s.exitChan)
	}()

	select {
	case matches := <-c:
		s.checkURL = matches[1]
		s.checkURLAlt = strings.Replace(matches[2], "0.0.0.0", "localhost", 1)
		s.logger.Infof("viam-server restart allowed check URLs: %s %s", s.checkURL, s.checkURLAlt)
		s.logger.Infof("%s started", SubsysName)

		// Once the subsystem has successfully started, check whether it handles needs restart
		// logic. We can calculate this value only once at startup and cache it, with the
		// assumption that it will not change over the course of the lifetime of the
		// subsystem.
		s.mu.Lock()
		s.doesNotHandleNeedsRestart, err = s.checkRestartProperty(ctx, RestartPropertyDoesNotHandleNeedsRestart)
		s.mu.Unlock()
		if err != nil {
			s.logger.Warn(err)
		}
		if !s.doesNotHandleNeedsRestart {
			s.logger.Warnf("%s may already handle checking needs restart functionality; will not handle in agent",
				SubsysName)
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(s.startTimeout):
		return errw.New("startup timed out")
	case <-s.exitChan:
		return errw.New("startup failed")
	}
}

func (s *viamServer) Stop(ctx context.Context) error {
	s.startStopMu.Lock()
	defer s.startStopMu.Unlock()

	s.mu.Lock()
	running := s.running
	s.shouldRun = false
	s.mu.Unlock()

	if !running {
		return nil
	}

	// interrupt early in startup
	if s.cmd == nil {
		return nil
	}

	s.logger.Infof("Stopping %s", SubsysName)
	if err := utils.SignalForTermination(s.cmd.Process.Pid); err != nil {
		s.logger.Warn(errw.Wrap(err, "signaling viam-server process"))
	}

	if s.waitForExit(ctx, stopTermTimeout) {
		s.logger.Infof("%s successfully stopped", SubsysName)
		return nil
	}

	s.logger.Warnf("%s refused to exit, killing", SubsysName)
	if err := utils.KillTree(s.cmd.Process.Pid); err != nil {
		s.logger.Warn(err)
	}

	if s.waitForExit(ctx, stopKillTimeout) {
		s.logger.Infof("%s successfully killed", SubsysName)
		return nil
	}

	return errw.Errorf("%s process couldn't be killed", SubsysName)
}

func (s *viamServer) waitForExit(ctx context.Context, timeout time.Duration) bool {
	s.mu.Lock()
	exitChan := s.exitChan
	running := s.running
	s.mu.Unlock()

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

// HealthCheck for viam server is unimplemented.
func (s *viamServer) HealthCheck(ctx context.Context) error {
	return nil
}

func (s *viamServer) Update(ctx context.Context, cfg utils.AgentConfig) (needRestart bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.startTimeout = time.Duration(cfg.AdvancedSettings.ViamServerStartTimeoutMinutes)

	if !reflect.DeepEqual(cfg.AdvancedSettings.ViamServerExtraEnvVars, s.extraEnvVars) {
		s.logger.Infow("Detected changed environment variables. Restarting viam-server at next opportunity.",
			"current", cfg.AdvancedSettings.ViamServerExtraEnvVars,
			"previous", s.extraEnvVars)
		s.extraEnvVars = cfg.AdvancedSettings.ViamServerExtraEnvVars
		return true
	}
	return false
}

// Property returns a single property of the currently running viamserver.
func (s *viamServer) Property(ctx context.Context, property string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch property {
	case RestartPropertyRestartAllowed:
		if !s.running || runtime.GOOS == "windows" {
			// Assume agent can restart viamserver if the subsystem is not running or we are
			// running on Windows.
			return true
		}

		restartAllowed, err := s.checkRestartProperty(ctx, RestartPropertyRestartAllowed)
		if err != nil {
			s.logger.Warn(err)
		}
		return restartAllowed
	case RestartPropertyDoesNotHandleNeedsRestart:
		// We can use the cached value (calculated in Start) for handle needs restart
		// property.
		return s.doesNotHandleNeedsRestart
	default:
		s.logger.Errorw("Unknown property requested from viamserver", "property", property)
		return false
	}
}

func NewSubsystem(ctx context.Context, logger logging.Logger, cfg utils.AgentConfig) subsystems.Subsystem {
	return &viamServer{
		logger:       logger,
		startTimeout: time.Duration(cfg.AdvancedSettings.ViamServerStartTimeoutMinutes),
		extraEnvVars: cfg.AdvancedSettings.ViamServerExtraEnvVars,
	}
}
