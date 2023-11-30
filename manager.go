package agent

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/viamrobotics/agent/subsystems"
	"github.com/viamrobotics/agent/subsystems/registry"
	"go.uber.org/zap"
	pb "go.viam.com/api/app/agent/v1"
	"go.viam.com/utils/rpc"
)

const (
	minimalCheckInterval = time.Second * 60
	agentCachePath       = "agent-config.json"
)

// Manager is the core of the agent process, and maintains the list of subsystems, as well as cloud connection.
type Manager struct {
	activeBackgroundWorkers sync.WaitGroup

	connMu      sync.RWMutex
	conn        rpc.ClientConn
	client      pb.AgentDeviceServiceClient
	partID      string
	cloudAddr   string
	cloudSecret string

	subsystemsMu     sync.Mutex
	loadedSubsystems map[string]subsystems.Subsystem
}

// NewManager returns a new Manager.
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
		cloudAddr:        cloud["app_address"],
		partID:           cloud["id"],
		cloudSecret:      cloud["secret"],
		loadedSubsystems: make(map[string]subsystems.Subsystem),
	}

	return manager, manager.LoadSubsystems(ctx, logger)
}

// SelfUpdate is called early in startup to update the viam-agent subsystem before any other work is started.
func (m *Manager) SelfUpdate(ctx context.Context, logger *zap.SugaredLogger) (bool, error) {
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	m.subsystemsMu.Lock()
	subsys, ok := m.loadedSubsystems["viam-agent"]
	m.subsystemsMu.Unlock()
	if !ok {
		logger.Warn("cannot load viam-agent subsystem")
	}
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

// SubsystemUpdates checks for updates to configured subsystems and restarts them as needed.
func (m *Manager) SubsystemUpdates(ctx context.Context, logger *zap.SugaredLogger, cfg map[string]*pb.DeviceSubsystemConfig) {
	if ctx.Err() != nil {
		return
	}
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

// CheckUpdates retrieves an updated config from the cloud, and then passes it to SubsystemUpdates().
func (m *Manager) CheckUpdates(ctx context.Context, logger *zap.SugaredLogger) time.Duration {
	logger.Debug("Checking cloud for update")
	cfg, interval, err := m.GetConfig(ctx, logger)

	// randomly fuzz the interval by +/- 5%
	interval = fuzzTime(interval, 0.05)

	if err != nil {
		logger.Error(err)
		return interval
	}

	// update and (re)start subsystems
	m.SubsystemUpdates(ctx, logger, cfg)

	return interval
}

// SubsystemHealthChecks makes sure all subsystems are responding, and restarts them if not.
func (m *Manager) SubsystemHealthChecks(ctx context.Context, logger *zap.SugaredLogger) {
	if ctx.Err() != nil {
		return
	}
	logger.Debug("Starting health checks for all subsystems")
	m.subsystemsMu.Lock()
	defer m.subsystemsMu.Unlock()
	for subsystemName, sub := range m.loadedSubsystems {
		ctxTimeout, cancelFunc := context.WithTimeout(ctx, time.Second*15)
		if err := sub.HealthCheck(ctxTimeout); err != nil {
			logger.Error("subsystem healthcheck failed for %s", subsystemName)
			if err := sub.Stop(ctx); err != nil {
				logger.Error(errors.Wrapf(err, "stopping subsystem %s", subsystemName))
			}
			if err := sub.Start(ctx); err != nil {
				logger.Error(errors.Wrapf(err, "restarting subsystem %s", subsystemName))
			}
		}
		cancelFunc()
	}
}

// CloseAll stops all subsystems and closes the cloud connection.
func (m *Manager) CloseAll(ctx context.Context, logger *zap.SugaredLogger) {
	if ctx.Err() != nil {
		return
	}

	m.subsystemsMu.Lock()
	defer m.subsystemsMu.Unlock()
	// close all subsystems
	for _, sub := range m.loadedSubsystems {
		if err := sub.Stop(ctx); err != nil {
			logger.Error(err)
		}
	}
	m.activeBackgroundWorkers.Wait()

	m.connMu.Lock()
	defer m.connMu.Unlock()
	err := m.conn.Close()
	if err != nil {
		logger.Error(err)
	}
	m.client = nil
	m.conn = nil
}

// StartBackgroundChecks kicks off a go routine that loops on a timer to check for updates and health checks.
func (m *Manager) StartBackgroundChecks(ctx context.Context, logger *zap.SugaredLogger) {
	if ctx.Err() != nil {
		return
	}
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
	if ctx.Err() != nil {
		return ctx.Err()
	}
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

// getCachedConfig returns a cached config, for when the cloud is not reachable.
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

// saveCachedConfig saves a local copy of the config normally fetched from the cloud.
func (m *Manager) saveCachedConfig(cfg map[string]*pb.DeviceSubsystemConfig) error {
	cacheFilePath := filepath.Join(ViamDirs["cache"], agentCachePath)

	cacheData, err := json.Marshal(cfg)
	if err != nil {
		return err
	}

	return os.WriteFile(cacheFilePath, cacheData, 0o644)
}

// dial establishes a connection to the cloud for grpc communication.
func (m *Manager) dial(ctx context.Context, logger *zap.SugaredLogger) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	m.connMu.Lock()
	defer m.connMu.Unlock()
	if m.client != nil {
		return nil
	}

	u, err := url.Parse(m.cloudAddr)
	if err != nil {
		return err
	}

	dialOpts := make([]rpc.DialOption, 0, 2)
	// Only add credentials when secret is set.
	if m.cloudSecret != "" {
		dialOpts = append(dialOpts, rpc.WithEntityCredentials(m.partID,
			rpc.Credentials{
				Type:    "robot-secret",
				Payload: m.cloudSecret,
			},
		))
	}

	if u.Scheme == "http" {
		dialOpts = append(dialOpts, rpc.WithInsecure())
	}

	conn, err := rpc.DialDirectGRPC(ctx, u.Host, logger, dialOpts...)
	if err != nil {
		return err
	}
	m.conn = conn
	m.client = pb.NewAgentDeviceServiceClient(m.conn)
	return nil
}

// GetConfig retrieves the configuration from the cloud, or returns a cached version if unable to communicate.
func (m *Manager) GetConfig(ctx context.Context, logger *zap.SugaredLogger) (map[string]*pb.DeviceSubsystemConfig, time.Duration, error) {
	if err := m.dial(ctx, logger); err != nil {
		logger.Error(errors.Wrap(err, "error fetching viam-agent config"))
		conf, err := m.getCachedConfig()
		return conf, minimalCheckInterval, err
	}

	req := &pb.DeviceAgentConfigRequest{
		Id:                m.partID,
		HostInfo:          m.getHostInfo(),
		SubsystemVersions: m.getSubsystemVersions(),
	}
	resp, err := m.client.DeviceAgentConfig(ctx, req)
	if err != nil {
		logger.Error(errors.Wrap(err, "error fetching viam-agent config"))
		conf, err := m.getCachedConfig()
		return conf, minimalCheckInterval, err
	}

	logger.Debugf("Cloud-provided config: %+v", resp)

	err = m.saveCachedConfig(resp.GetSubsystemConfigs())
	if err != nil {
		logger.Error(errors.Wrap(err, "error saving agent config to cache"))
	}

	interval := resp.GetCheckInterval().AsDuration()

	if interval < minimalCheckInterval {
		interval = minimalCheckInterval
	}

	return resp.GetSubsystemConfigs(), interval, nil
}

func (m *Manager) getHostInfo() *pb.HostInfo {
	pbInfo := &pb.HostInfo{Platform: runtime.GOOS + "/" + runtime.GOARCH}
	info, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return pbInfo
	}

	distroRegex := regexp.MustCompile(`^ID="?(.+)"?`)
	versionRegex := regexp.MustCompile(`^VERSION_ID="?(.+)"?`)

	matches := distroRegex.FindStringSubmatch(string(info))
	if len(matches) > 1 {
		pbInfo.Distro = matches[1]
	} else {
		return pbInfo
	}

	matches = versionRegex.FindStringSubmatch(string(info))
	if len(matches) > 1 {
		pbInfo.Distro = pbInfo.GetDistro() + ":" + matches[1]
	} else {
		pbInfo.Distro = pbInfo.GetDistro() + ":" + "unknown"
	}
	// Check for specific SBCs
	// Only Raspberry Pi for now
	if pbInfo.GetPlatform() == "linux/arm64" || pbInfo.GetPlatform() == "linux/arm" {
		info, err = os.ReadFile("/sys/firmware/devicetree/base/compatible")
		if err != nil {
			return pbInfo
		}

		if strings.Contains(string(info), "raspberrypi") {
			pbInfo.Tags = append(pbInfo.GetTags(), "rpi")
			if strings.Contains(string(info), "4-model-bbrcm") {
				pbInfo.Tags = append(pbInfo.GetTags(), "rpi4")
			}
		}
	}

	return pbInfo
}

func (m *Manager) getSubsystemVersions() map[string]string {
	m.subsystemsMu.Lock()
	defer m.subsystemsMu.Unlock()
	vers := make(map[string]string)
	for name, sys := range m.loadedSubsystems {
		vers[name] = sys.Version()
	}
	return vers
}
