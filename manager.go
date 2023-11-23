package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/viamrobotics/agent/subsystems"
	"github.com/viamrobotics/agent/subsystems/registry"
	"go.uber.org/zap"
	pb "go.viam.com/api/app/agent/v1"
	"go.viam.com/utils/rpc"
)

type Manager struct {
	activeBackgroundWorkers sync.WaitGroup

	mu          sync.Mutex
	conn        rpc.ClientConn
	client      pb.AgentDeviceServiceClient
	partID      string
	cloudAddr   string
	cloudSecret string

	subsystemsMu     sync.Mutex
	loadedSubsystems map[string]subsystems.Subsystem
}

func NewManager(ctx context.Context, logger *zap.SugaredLogger, cfgPath string) (*Manager, error) {
	logger.Debugw("loading", "config", cfgPath)
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, errors.Wrap(err, "error reading config file")
	}

	cfg := make(map[string]map[string]string)
	err = json.Unmarshal(b, &cfg)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing config file")
	}

	cloud, ok := cfg["cloud"]
	if !ok {
		return nil, errors.New("no cloud section in local config file")
	}

	for _, req := range []string{"app_address", "id", "secret"} {
		field, ok := cloud[req]
		if !ok {
			return nil, errors.Errorf("no cloud config field for %s", field)
		}
	}

	manager := &Manager{
		cloudAddr: cloud["app_address"],
		partID: cloud["id"],
		cloudSecret: cloud["secret"],
		loadedSubsystems: make(map[string]subsystems.Subsystem),
	}

	return manager, manager.LoadSubsystems(ctx, logger)
}

func (m *Manager) SelfUpdate(ctx context.Context, logger *zap.SugaredLogger) (bool, error) {
	m.subsystemsMu.Lock()
	subsys, ok := m.loadedSubsystems["viam-agent"]
	if !ok {
		logger.Warn("cannot load viam-agent subsystem")
	}
	m.subsystemsMu.Unlock()
	cfgMap, _, err := m.GetConfig(ctx, logger)
	if err != nil {
		return false, err
	}
	cfg, ok := cfgMap["viam-agent"]
	if !ok {
		return false, errors.New("no viam-agent section found in config")
	}
	return subsys.Update(ctx, cfg)
}

func (m *Manager) SubsystemUpdates(ctx context.Context, logger *zap.SugaredLogger, cfg map[string]*pb.DeviceSubsystemConfig) {
	m.subsystemsMu.Lock()
	defer m.subsystemsMu.Unlock()
	// stop/remove orphaned subsystems
	for key, sub := range m.loadedSubsystems {
		if _, ok := cfg[key]; !ok {
			if err := sub.Stop(ctx); err != nil {
				logger.Error(err)
				continue
			}
			delete(m.loadedSubsystems, key)
		}
	}

	// add new subsystems
	for name, subCfg := range cfg {
		if _, ok := m.loadedSubsystems[name]; !ok {
			err := m.loadSubsystem(ctx, logger, name, subCfg)
			if err != nil {
				logger.Warnw("couldn't load subsystem", "name", name, "error", err)
			}
		}
	}

	// check updates and (re)start
	for name, sub := range m.loadedSubsystems {
		cancelCtx, cancel := context.WithTimeout(ctx, time.Minute*5)
		defer cancel()
		restart, err := sub.Update(cancelCtx, cfg[name])
		if err != nil {
			logger.Error(err)
			continue
		}
		if restart {
			if err := sub.Stop(ctx); err != nil {
				logger.Error(err)
				continue
			}
		}
		if err := sub.Start(ctx); err != nil {
			logger.Error(err)
			continue
		}
	}
}

func (m *Manager) CheckUpdates(ctx context.Context, logger *zap.SugaredLogger) time.Duration {
	logger.Info("SMURF check for update")
	cfg, interval, err := m.GetConfig(ctx, logger)

	// randomly fuzz the interval by +/- 5%
	interval = fuzzTime(interval, 0.05)

	if err != nil {
		logger.Error(err)
		return interval
	}

	fmt.Println("SMURF CONFIG", cfg)

	// update and (re)start subsystems
	m.SubsystemUpdates(ctx, logger, cfg)

	return interval
}

func (m *Manager) SubsystemHealthChecks(ctx context.Context, logger *zap.SugaredLogger) {
	logger.Info("SMURF check statuses")
	m.subsystemsMu.Lock()
	defer m.subsystemsMu.Unlock()
	for _, sub := range m.loadedSubsystems {
		ctxTimeout, cancelFunc := context.WithTimeout(ctx, time.Second*15)
		if err := sub.HealthCheck(ctxTimeout); err != nil {
			logger.Error("subsystem healthcheck failed")
			if err := sub.Stop(ctx); err != nil {
				logger.Error(errors.Wrap(err, "stopping subsystem"))
			}
			if err := sub.Start(ctx); err != nil {
				logger.Error(errors.Wrap(err, "restarting subsystem"))
			}
		}
		cancelFunc()
	}
}

func (m *Manager) CloseAll(ctx context.Context, logger *zap.SugaredLogger) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.subsystemsMu.Lock()
	defer m.subsystemsMu.Unlock()
	// close all subsystems
	for _, sub := range m.loadedSubsystems {
		if err := sub.Stop(ctx); err != nil {
			logger.Error(err)
		}
	}
	m.activeBackgroundWorkers.Wait()

	err := m.conn.Close()
	if err != nil {
		logger.Error(err)
	}
	m.client = nil
	m.conn = nil
}

func (m *Manager) StartBackgroundChecks(ctx context.Context, logger *zap.SugaredLogger) {
	m.activeBackgroundWorkers.Add(1)
	go func() {
		checkInterval := m.CheckUpdates(ctx, logger)
		timer := time.NewTimer(checkInterval)
		defer timer.Stop()
		defer m.activeBackgroundWorkers.Done()
		for {
			if ctx.Err() != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			// case <-sigHUP:
			// 	checkUpdates(ctx)
			case <-timer.C:
				checkInterval = m.CheckUpdates(ctx, logger)
				m.SubsystemHealthChecks(ctx, logger)
				timer.Reset(checkInterval)
			}
		}
	}()
}

// LoadSubsystems runs at startup, before getting online.
func (m *Manager) LoadSubsystems(ctx context.Context, logger *zap.SugaredLogger) error {
	m.subsystemsMu.Lock()
	defer m.subsystemsMu.Unlock()

	cachedConfig, err := m.getCachedConfig()
	if err != nil {
		logger.Error(errors.Wrap(err, "error getting cached config"))
	}

	for name, subsys := range cachedConfig {
		err := m.loadSubsystem(ctx, logger, name, subsys)
		if err != nil {
			logger.Warnw("couldn't load subsystem", "name", name, "error", err)
		}
	}

	return nil
}

// loadSubsystem needs to be called inside a lock.
func (m *Manager) loadSubsystem(ctx context.Context, logger *zap.SugaredLogger, name string, subCfg *pb.DeviceSubsystemConfig) error {
	creator := registry.GetCreator(name)
	if creator != nil {
		sub, err := creator(ctx, logger, subCfg)
		if err != nil {
			return err
		}
		m.loadedSubsystems[name] = sub
		return nil
	}
	return errors.Errorf("unknown subsystem name %s", name)
}

func (m *Manager) getCachedConfig() (map[string]*pb.DeviceSubsystemConfig, error) {
	// return a bare-minimum for self-update on new installs or for fallback	
	cachedConfig := map[string]*pb.DeviceSubsystemConfig{"viam-agent": {}}

	cacheFilePath := filepath.Join(ViamDirs["cache"], agentCachePath)
	cacheBytes, err := os.ReadFile(cacheFilePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return cachedConfig, nil
		}
		return nil, errors.Wrap(err, "error reading cached config")
	}

	err = json.Unmarshal(cacheBytes, &cachedConfig)
	if err != nil {
		return nil, errors.Wrapf(err, "error parsing cached config")
	}
	return cachedConfig, nil
}

func (m *Manager) saveCachedConfig(cfg map[string]*pb.DeviceSubsystemConfig) error {
	cacheFilePath := filepath.Join(ViamDirs["cache"], agentCachePath)

	cacheData, err := json.Marshal(cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(cacheFilePath, cacheData, 0o644)
}
