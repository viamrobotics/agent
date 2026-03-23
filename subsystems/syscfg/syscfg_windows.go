//go:build windows

package syscfg

import (
	"context"
	"errors"
	"reflect"
	"sync"

	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
)

// Subsystem manages Windows Update (via PSWindowsUpdate/WSUS) on Windows.
type Subsystem struct {
	mu      sync.RWMutex
	cfg     utils.SystemConfiguration
	logger  logging.Logger
	started bool
	healthy bool

	// Managed OS upgrades (used when OSAutoUpgradeType is "managed-security" or "managed-all")
	needsOSReboot bool
	upgradeCancel context.CancelFunc
	upgradeWorker sync.WaitGroup
}

func New(_ context.Context, logger logging.Logger, cfg utils.AgentConfig, _ func() logging.Appender, _ bool) *Subsystem {
	return &Subsystem{
		logger: logger,
		cfg:    cfg.SystemConfiguration,
	}
}

func (s *Subsystem) Update(_ context.Context, cfg utils.AgentConfig) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := !reflect.DeepEqual(cfg.SystemConfiguration, s.cfg)
	s.cfg = cfg.SystemConfiguration
	return changed
}

func (s *Subsystem) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return nil
	}
	s.logger.Info("Starting syscfg subsystem")
	s.started = true
	s.healthy = true

	mode := s.cfg.OSAutoUpgradeType
	if mode == managedSecurityMode || mode == "managed-all" {
		s.startManagedUpgrades(ctx)
	}
	return nil
}

func (s *Subsystem) Stop(_ context.Context) error {
	s.mu.Lock()
	wasStarted := s.started
	s.started = false
	cancel := s.upgradeCancel
	s.upgradeCancel = nil
	s.mu.Unlock()

	if wasStarted {
		s.logger.Info("Stopping syscfg subsystem")
	}
	if cancel != nil {
		cancel()
		s.upgradeWorker.Wait()
	}
	return nil
}

func (s *Subsystem) HealthCheck(_ context.Context) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.healthy {
		return nil
	}
	return errors.New("healthcheck failed")
}
