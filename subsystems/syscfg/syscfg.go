// Package syscfg contains the system configuration agent subsystem.
package syscfg

import (
	"context"
	"errors"
	"reflect"
	"sync"

	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/subsystems"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
)

const (
	SubsysName = "agent-syscfg"
)

type syscfg struct {
	mu      sync.RWMutex
	healthy bool
	cfg     utils.SystemConfiguration
	logger  logging.Logger
	running bool
	cancel  context.CancelFunc
	workers sync.WaitGroup
}

func NewSubsystem(ctx context.Context, logger logging.Logger, cfg utils.AgentConfig) subsystems.Subsystem {
	return &syscfg{
		logger: logger,
		cfg:    cfg.SystemConfiguration,
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

func (s *syscfg) Version() string {
	return utils.GetVersion()
}

func (s *syscfg) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// prevent double-starts
	if s.running {
		return errors.New("already running")
	}

	cancelCtx, cancelFunc := context.WithCancel(ctx)
	s.cancel = cancelFunc
	s.running = true
	s.workers.Add(1)
	go func() {
		var healthyLog, healthyUpgrades bool
		defer func() {
			// if something panicked, log it and allow things to continue
			r := recover()
			if r != nil {
				s.logger.Error("syscfg subsystem encountered a panic")
				s.logger.Error(r)
			}

			s.mu.Lock()
			s.healthy = healthyLog && healthyUpgrades
			s.running = false
			s.workers.Done()
			s.mu.Unlock()
		}()

		// set journald max size limits
		err := s.EnforceLogging()
		if err != nil {
			s.logger.Error(errw.Wrap(err, "configuring journald logging"))
		}
		healthyLog = true

		// set unattended upgrades
		err = s.EnforceUpgrades(cancelCtx)
		if err != nil {
			s.logger.Error(errw.Wrap(err, "configuring unattended upgrades"))
		}
		healthyUpgrades = true
	}()

	return nil
}

func (s *syscfg) Stop(ctx context.Context) error {
	s.mu.RLock()
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.RUnlock()
	s.workers.Wait()
	return nil
}

func (s *syscfg) HealthCheck(ctx context.Context) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.healthy {
		return nil
	}
	return errors.New("healthcheck failed")
}
