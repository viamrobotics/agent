// Package viamserver contains the viam-server agent subsystem.
package viamserver

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"os/exec"
	"path"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent"
	"github.com/viamrobotics/agent/subsystems"
	"github.com/viamrobotics/agent/subsystems/registry"
	pb "go.viam.com/api/app/agent/v1"
	"go.viam.com/rdk/logging"
	"google.golang.org/protobuf/types/known/structpb"
)

func init() {
	globalConfig.Store(&viamServerConfig{startTimeout: defaultStartTimeout})
	registry.Register(SubsysName, NewSubsystem)
}

type viamServerConfig struct {
	startTimeout time.Duration
}

const (
	defaultStartTimeout = time.Minute * 5
	// stopTermTimeout must be higher than viam-server shutdown timeout of 90 secs.
	stopTermTimeout = time.Minute * 2
	stopKillTimeout = time.Second * 10
	fastStartName   = "fast_start"
	SubsysName      = "viam-server"
)

var (
	ConfigFilePath = "/etc/viam.json"

	// Set if (cached or cloud) config has the "fast_start" attribute set on the viam-server subsystem.
	FastStart    atomic.Bool
	globalConfig atomic.Pointer[viamServerConfig]
)

type viamServer struct {
	mu          sync.Mutex
	cmd         *exec.Cmd
	running     bool
	shouldRun   bool
	lastExit    int
	exitChan    chan struct{}
	checkURL    string
	checkURLAlt string

	// for blocking start/stop/check ops while another is in progress
	startStopMu sync.Mutex

	logger logging.Logger
}

// helper to parse a duration, otherwise return a default.
func durationFromProtoStruct(
	logger logging.Logger, protoStruct *structpb.Struct, key string, defaultValue time.Duration,
) time.Duration {
	if protoStruct == nil {
		return defaultValue
	}
	asMap := protoStruct.AsMap()
	raw, ok := asMap[key]
	if !ok {
		return defaultValue
	}
	str, ok := raw.(string)
	if !ok {
		return defaultValue
	}
	durt, err := time.ParseDuration(str)
	if err != nil {
		logger.Warnf("unparseable duration string at %s: %s, error %s", key, str, err)
		return defaultValue
	}
	logger.Debugf("parsed duration %s from key %s", durt.String(), key)
	return durt
}

func configFromProto(logger logging.Logger, updateConf *pb.DeviceSubsystemConfig) *viamServerConfig {
	ret := &viamServerConfig{}
	if updateConf != nil {
		ret.startTimeout = durationFromProtoStruct(logger, updateConf.GetAttributes(), "start_timeout", defaultStartTimeout)
	}
	return ret
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

	stdio := agent.NewMatchingLogger(s.logger, false, false)
	stderr := agent.NewMatchingLogger(s.logger, true, false)
	//nolint:gosec
	s.cmd = exec.Command(path.Join(agent.ViamDirs["bin"], SubsysName), "-config", ConfigFilePath)
	s.cmd.Dir = agent.ViamDirs["viam"]
	s.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
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
	case <-time.After(globalConfig.Load().startTimeout):
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
	err = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
	if err != nil {
		s.logger.Error(err)
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
			errRet = errors.Join(errRet, resp.Body.Close())
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

func (s *viamServer) Update(ctx context.Context, cfg *pb.DeviceSubsystemConfig, newVersion bool) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	setFastStart(cfg)
	if newVersion && s.running {
		s.logger.Info("awaiting user restart to run new viam-server version")
		s.shouldRun = false
	}
	globalConfig.Store(configFromProto(s.logger, cfg))
	// always return false on the needRestart flag, as we await the user to kill/restart viam-server directly
	return false, nil
}

func NewSubsystem(ctx context.Context, logger logging.Logger, updateConf *pb.DeviceSubsystemConfig) (subsystems.Subsystem, error) {
	setFastStart(updateConf)

	globalConfig.Store(configFromProto(logger, updateConf))
	return agent.NewAgentSubsystem(ctx, SubsysName, logger, &viamServer{logger: logger})
}

func setFastStart(cfg *pb.DeviceSubsystemConfig) {
	if cfg != nil {
		cfgVal, ok := cfg.GetAttributes().AsMap()[fastStartName]
		if ok {
			cfgBool, ok := cfgVal.(bool)
			if ok {
				FastStart.Store(cfgBool)
				return
			}
		}
	}
	FastStart.Store(false)
}
