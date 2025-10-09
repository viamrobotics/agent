// Package viamserver contains the viam-server agent subsystem.
package viamserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
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

	// extra environment variables to set before launching server
	extraEnvVars map[string]string

	// for blocking start/stop/check ops while another is in progress
	startStopMu sync.Mutex

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

	// suppress specific panic patterns from stdout to prevent double logging
	_, err = stdio.AddMatcher(
		"panicSuppressor",
		regexp.MustCompile(`^panic:`),
		true,
	)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	defer stdio.DeleteMatcher("panicSuppressor")

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

// errUnsafeToRestart is reported to a result channel in isRestartAllowed below when any
// one of the viam-server test URLs explicitly reports that it is unsafe to restart
// the viam-server instance.
var errUnsafeToRestart = errors.New("viam-server reports it is unsafe to restart")

// Must be called with `s.mu` held, as `s.checkURL` and `s.checkURLAlt` are
// both accessed.
func (s *viamServer) isRestartAllowed(ctx context.Context) (bool, error) {
	urls, err := s.makeTestURLs()
	if err != nil {
		return false, err
	}

	resultChan := make(chan error, len(urls))

	timeoutCtx, cancelFunc := context.WithTimeout(ctx, time.Second*10)
	defer cancelFunc()

	for _, url := range urls {
		go func() {
			s.logger.Debugf("starting restart allowed check for %s using %s", SubsysName, url)

			restartURL := url + "/restart_status"

			req, err := http.NewRequestWithContext(timeoutCtx, http.MethodGet, restartURL, nil)
			if err != nil {
				resultChan <- errw.Wrapf(err, "checking whether %s allows restart via %s", SubsysName, restartURL)
				return
			}

			// disabling the cert verification because it doesn't work in offline mode (when connecting to localhost)
			//nolint:gosec
			client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

			resp, err := client.Do(req)
			if err != nil {
				resultChan <- errw.Wrapf(err, "checking whether %s allows restart via %s", SubsysName, restartURL)
				return
			}

			defer func() {
				goutils.UncheckedError(resp.Body.Close())
			}()

			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				// Interacting with older viam-server instances will result in a
				// non-successful HTTP response status code, as the `restart_status`
				// endpoint will not be available. Continue to next URL in this
				// case.
				resultChan <- errw.Wrapf(err, "checking %s status via %s, got code: %d", SubsysName, restartURL, resp.StatusCode)
				return
			}

			var restartStatusResponse RestartStatusResponse
			if err = json.NewDecoder(resp.Body).Decode(&restartStatusResponse); err != nil {
				resultChan <- errw.Wrapf(err, "checking whether %s allows restart via %s", SubsysName, restartURL)
				return
			}
			if restartStatusResponse.RestartAllowed {
				resultChan <- nil
				return
			}
			resultChan <- errUnsafeToRestart
		}()
	}

	var combinedErr error
	for i := 1; i <= len(urls); i++ {
		result := <-resultChan

		// If any test URL reports it is explicitly _safe_ to restart (nil value sent to
		// resultChan), we can assume we can restart viam-server.
		if result == nil {
			return true, nil
		}
		// If any test URL reports it is explicitly _unsafe_ to restart (errUnsafeToRestart),
		// we can assume we should not restart viam-server.
		if errors.Is(result, errUnsafeToRestart) {
			return false, errUnsafeToRestart
		}

		combinedErr = errors.Join(combinedErr, result)
	}
	return false, combinedErr
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

func (s *viamServer) SafeToRestart(ctx context.Context) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running || runtime.GOOS == "windows" {
		return true
	}

	// viam-server can be safely restarted even while running if the process
	// has reported it is safe to do so through its `restart_status` HTTP
	// endpoint.
	restartAllowed, err := s.isRestartAllowed(ctx)
	if err != nil {
		s.logger.Warn(err)
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
		extraEnvVars: cfg.AdvancedSettings.ViamServerExtraEnvVars,
	}
}

type RestartCheck interface {
	SafeToRestart(ctx context.Context) bool
}

// must be called with s.mu locked.
func (s *viamServer) makeTestURLs() ([]string, error) {
	port := "8080"
	mainURL, err := url.Parse(s.checkURL)
	if err != nil {
		s.logger.Warnf("cannot determine port for restart allowed check, using default of 8080")
	} else {
		port = mainURL.Port()
		s.logger.Debugf("using port %s for restart allowed check", port)
	}

	ips, err := GetAllLocalIPv4s()
	if err != nil {
		return []string{}, err
	}

	urls := []string{s.checkURL, s.checkURLAlt}
	for _, ip := range ips {
		urls = append(urls, fmt.Sprintf("https://%s:%s", ip, port))
	}

	return urls, nil
}

// GetAllLocalIPv4s is copied from goutils, but removed the loopback checks, as we DO want loopback adapters.
func GetAllLocalIPv4s() ([]string, error) {
	allInterfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	all := []string{}

	for _, i := range allInterfaces {
		addrs, err := i.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				_, bits := v.Mask.Size()
				if bits != 32 {
					// this is what limits to ipv4
					continue
				}

				all = append(all, v.IP.String())
			default:
				return nil, fmt.Errorf("unknown address type: %T", v)
			}
		}
	}

	return all, nil
}
