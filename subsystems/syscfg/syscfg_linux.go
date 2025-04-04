package syscfg

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"sync"

	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/subsystems"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
)

type syscfg struct {
	mu      sync.RWMutex
	cfg     utils.SystemConfiguration
	logger  logging.Logger
	healthy bool
	started bool

	// Log Forwarding
	logMu      sync.Mutex
	logWorkers sync.WaitGroup
	appender   func() logging.Appender
	logHealth  *utils.Health
	journalCmd *exec.Cmd
	cancelFunc context.CancelFunc
	noJournald bool
}

func NewSubsystem(ctx context.Context,
	logger logging.Logger,
	cfg utils.AgentConfig,
	getAppenderFunc func() logging.Appender,
) subsystems.Subsystem {
	return &syscfg{
		appender:  getAppenderFunc,
		logger:    logger,
		cfg:       cfg.SystemConfiguration,
		logHealth: utils.NewHealth(),
	}
}

func (s *syscfg) Update(ctx context.Context, cfg utils.AgentConfig) (needRestart bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !reflect.DeepEqual(cfg.SystemConfiguration, s.cfg) {
		needRestart = true
	}

	s.cfg = cfg.SystemConfiguration
	return
}

func (s *syscfg) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// prevent pointless runs if it already ran to completion
	if s.started {
		return nil
	}

	s.logger.Debugf("Starting syscfg")

	s.started = true
	var healthyLog, healthyUpgrades bool
	defer func() {
		// if something panicked, log it and allow things to continue
		r := recover()
		if r != nil {
			s.logger.Error("syscfg subsystem encountered a panic")
			s.logger.Error(r)
		}

		s.healthy = healthyLog && healthyUpgrades
	}()

	// set journald max size limits
	err := s.EnforceLogging()
	if err != nil {
		s.logger.Error(errw.Wrap(err, "configuring journald logging"))
	}
	healthyLog = true

	// set unattended upgrades
	err = s.EnforceUpgrades(ctx)
	if err != nil {
		s.logger.Error(errw.Wrap(err, "configuring unattended upgrades"))
	}
	healthyUpgrades = true

	// start kernel log forwarding
	err = s.startLogForwarding()
	if err != nil {
		s.logger.Error(errw.Wrap(err, "starting kernel log forwarding"))
	}

	return nil
}

func (s *syscfg) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.started = false

	if err := s.stopLogForwarding(); err != nil {
		s.logger.Error(errw.Wrap(err, "stopping kernel log forwarding"))
	}
	return nil
}

func (s *syscfg) HealthCheck(ctx context.Context) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.healthy && s.logHealth.IsHealthy() {
		return nil
	}
	return errors.New("healthcheck failed")
}
