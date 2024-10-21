// Package syscfg contains the system configuration agent subsystem.
package syscfg

import (
	"context"
	"errors"
	"reflect"
	"sync"

	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent"
	"github.com/viamrobotics/agent/subsystems"
	"github.com/viamrobotics/agent/subsystems/registry"
	pb "go.viam.com/api/app/agent/v1"
	"go.viam.com/rdk/logging"
)

func init() {
	registry.Register(SubsysName, NewSubsystem)
}

const (
	SubsysName = "agent-syscfg"
)

type Config struct {
	Logging  LogConfig      `json:"logging"`
	Upgrades UpgradesConfig `json:"upgrades"`
}

type syscfg struct {
	mu       sync.RWMutex
	healthy  bool
	cfg      Config
	logger   logging.Logger
	running  bool
	disabled bool
	cancel   context.CancelFunc
	workers  sync.WaitGroup
}

func NewSubsystem(ctx context.Context, logger logging.Logger, updateConf *pb.DeviceSubsystemConfig) (subsystems.Subsystem, error) {
	cfg, err := agent.ConvertAttributes[Config](updateConf.GetAttributes())
	if err != nil {
		return nil, err
	}

	return &syscfg{cfg: *cfg, logger: logger, disabled: updateConf.GetDisable()}, nil
}

func (s *syscfg) Update(ctx context.Context, cfg *pb.DeviceSubsystemConfig) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var needRestart bool
	if cfg.GetDisable() != s.disabled {
		s.disabled = cfg.GetDisable()
		needRestart = true
	}

	if s.disabled {
		return needRestart, nil
	}

	newConf, err := agent.ConvertAttributes[Config](cfg.GetAttributes())
	if err != nil {
		return needRestart, err
	}

	if reflect.DeepEqual(newConf, s.cfg) {
		return needRestart, nil
	}

	needRestart = true
	s.cfg = *newConf
	return needRestart, nil
}

func (s *syscfg) Version() string {
	return agent.GetVersion()
}

func (s *syscfg) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// prevent double-starts
	if s.running {
		return errors.New("already running")
	}

	if s.disabled {
		s.logger.Infof("agent-syscfg disabled")
		return agent.ErrSubsystemDisabled
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
	if s.healthy || s.disabled {
		return nil
	}
	return errors.New("healthcheck failed")
}
