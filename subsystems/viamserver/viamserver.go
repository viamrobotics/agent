// Package viamserver contains the viam-server agent subsystem.
package viamserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/subsystems"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
	goutils "go.viam.com/utils"
)

const (
	// stopTermTimeout must be higher than viam-server shutdown timeout of 90 secs.
	stopTermTimeout = time.Minute * 2
	stopKillTimeout = time.Second * 10
	SubsysName      = "viam-server"
)

// RestartStatusResponse is the http/json response from viam_server's /health_check URL
// This MUST remain in sync with RDK.
type RestartStatusResponse struct {
	// RestartAllowed represents whether this instance of the viam-server can be
	// safely restarted.
	RestartAllowed bool `json:"restart_allowed"`
}

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

	// for blocking start/stop/check ops while another is in progress
	startStopMu sync.Mutex

	logger logging.Logger
}

func (s *viamServer) Start(ctx context.Context) error {
	s.startStopMu.Lock()
	defer s.startStopMu.Unlock()

	s.mu.Lock()

	if s.running {
		s.mu.Unlock()
		return nil
	}
	if s.shouldRun {
		s.logger.Warnf("Restarting %s after unexpected exit", SubsysName)
	} else {
		s.logger.Infof("Starting %s", SubsysName)
		s.shouldRun = true
	}

	stdio := utils.NewMatchingLogger(s.logger, false, false)
	stderr := utils.NewMatchingLogger(s.logger, true, false)
	//nolint:gosec
	s.cmd = exec.Command(path.Join(utils.ViamDirs["bin"], SubsysName), "-config", utils.AppConfigFilePath)
	s.cmd.Dir = utils.ViamDirs["viam"]
	utils.PlatformProcSettings(s.cmd)
	s.cmd.Stdout = stdio
	s.cmd.Stderr = stderr

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
		err := s.cmd.Wait()
		s.mu.Lock()
		defer s.mu.Unlock()
		s.running = false
		s.logger.Infof("%s exited", SubsysName)
		if err != nil {
			s.logger.Errorw("error while getting process status", "error", err)
		}
		if s.cmd.ProcessState != nil {
			s.lastExit = s.cmd.ProcessState.ExitCode()
			if s.lastExit != 0 {
				s.logger.Errorw("non-zero exit code", "exit code", s.lastExit)
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
		s.logger.Infof("healthcheck URLs: %s %s", s.checkURL, s.checkURLAlt)
		s.logger.Infof("%s started", SubsysName)
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

	err := s.cmd.Process.Signal(syscall.SIGTERM)
	if err != nil {
		s.logger.Error(err)
	}

	if s.waitForExit(ctx, stopTermTimeout) {
		s.logger.Infof("%s successfully stopped", SubsysName)
		return nil
	}

	s.logger.Warnf("%s refused to exit, killing", SubsysName)
	utils.PlatformKill(s.logger, s.cmd)

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

func (s *viamServer) HealthCheck(ctx context.Context) (errRet error) {
	s.startStopMu.Lock()
	defer s.startStopMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return errw.Errorf("%s not running", SubsysName)
	}
	if s.checkURL == "" {
		return errw.Errorf("can't find listening URL for %s", SubsysName)
	}

	for _, url := range []string{s.checkURL, s.checkURLAlt} {
		s.logger.Debugf("starting healthcheck for %s using %s", SubsysName, url)

		timeoutCtx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
		defer cancelFunc()

		req, err := http.NewRequestWithContext(timeoutCtx, http.MethodGet, url, nil)
		if err != nil {
			errRet = errors.Join(errRet, errw.Wrapf(err, "checking %s status", SubsysName))
			continue
		}

		// disabling the cert verification because it doesn't work in offline mode (when connecting to localhost)
		//nolint:gosec
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

		resp, err := client.Do(req)
		if err != nil {
			errRet = errors.Join(errRet, errw.Wrapf(err, "checking %s status", SubsysName))
			continue
		}

		defer func() {
			goutils.UncheckedError(resp.Body.Close())
		}()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			errRet = errors.Join(errRet, errw.Wrapf(err, "checking %s status, got code: %d", SubsysName, resp.StatusCode))
			continue
		}
		s.logger.Debugf("healthcheck for %s is good", SubsysName)
		return nil
	}

	return errRet
}

// Must be called with `s.mu` held, as `s.checkURL` and `s.checkURLAlt` are
// both accessed.
func (s *viamServer) isRestartAllowed(ctx context.Context) (bool, error) {
	for _, url := range []string{s.checkURL, s.checkURLAlt} {
		s.logger.Debugf("starting restart allowed check for %s using %s", SubsysName, url)

		ctx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
		defer cancelFunc()

		restartURL := url + "/restart_status"

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, restartURL, nil)
		if err != nil {
			return false, errw.Wrapf(err, "checking whether %s allows restart", SubsysName)
		}

		// disabling the cert verification because it doesn't work in offline mode (when connecting to localhost)
		//nolint:gosec
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

		resp, err := client.Do(req)
		if err != nil {
			if url == s.checkURL {
				// if this is only the first URL, we want to continue, not return, so log the error
				s.logger.Warn(errw.Wrapf(err, "checking whether %s allows restart", SubsysName))
				continue
			}
			return false, errw.Wrapf(err, "checking whether %s allows restart", SubsysName)
		}

		defer func() {
			goutils.UncheckedError(resp.Body.Close())
		}()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			// Interacting with older viam-server instances will result in a
			// non-successful HTTP response status code, as the `restart_status`
			// endpoint will not be available. Continue to next URL in this
			// case.
			continue
		}

		var restartStatusResponse RestartStatusResponse
		if err = json.NewDecoder(resp.Body).Decode(&restartStatusResponse); err != nil {
			return false, errw.Wrapf(err, "checking whether %s allows restart", SubsysName)
		}
		return restartStatusResponse.RestartAllowed, nil
	}
	return false, nil
}

func (s *viamServer) Update(ctx context.Context, cfg utils.AgentConfig) (needRestart bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.startTimeout = time.Duration(cfg.AdvancedSettings.ViamServerStartTimeoutMinutes)
	return false
}

func (s *viamServer) SafeToRestart(ctx context.Context) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return true
	}

	// viam-server can be safely restarted even while running if the process
	// has reported it is safe to do so through its `restart_status` HTTP
	// endpoint.
	restartAllowed, err := s.isRestartAllowed(ctx)
	if err != nil {
		s.logger.Error(err)
		return restartAllowed
	}
	if restartAllowed {
		s.logger.Infof("will restart %s to run new version, as it has reported allowance of a restart", SubsysName)
	} else {
		s.logger.Infof("will not restart %s version to run new version, as it has not reported allowance of a restart", SubsysName)
	}
	return restartAllowed
}

func NewSubsystem(ctx context.Context, logger logging.Logger, cfg utils.AgentConfig) subsystems.Subsystem {
	return &viamServer{
		logger:       logger,
		startTimeout: time.Duration(cfg.AdvancedSettings.ViamServerStartTimeoutMinutes),
	}
}

type RestartCheck interface {
	SafeToRestart(ctx context.Context) bool
}
