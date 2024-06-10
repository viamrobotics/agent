package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/subsystems"
	"github.com/viamrobotics/agent/subsystems/registry"
	pb "go.viam.com/api/app/agent/v1"
	"go.viam.com/rdk/logging"
	"go.viam.com/utils/rpc"
)

const (
	minimalCheckInterval  = time.Second * 60
	defaultNetworkTimeout = time.Second * 15
	// stopAllTimeout must be lower than systemd subsystems/viamagent/viam-agent.service timeout of 4mins
	// and higher than subsystems/viamserver/viamserver.go timeout of 2mins.
	stopAllTimeout = time.Minute * 3
	agentCachePath = "agent-config.json"
	SubsystemName  = "viam-agent"
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

	logger logging.Logger

	subsystemsMu     sync.Mutex
	loadedSubsystems map[string]subsystems.Subsystem
}

// NewManager returns a new Manager.
func NewManager(ctx context.Context, logger logging.Logger) (*Manager, error) {
	manager := &Manager{
		logger:           logger,
		loadedSubsystems: make(map[string]subsystems.Subsystem),
	}

	return manager, manager.LoadSubsystems(ctx)
}

func (m *Manager) LoadConfig(cfgPath string) error {
	m.connMu.Lock()
	defer m.connMu.Unlock()

	m.logger.Debugw("loading", "config", cfgPath)
	//nolint:gosec
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		return errw.Wrap(err, "reading config file")
	}

	cfg := make(map[string]map[string]string)
	err = json.Unmarshal(b, &cfg)
	if err != nil {
		return errw.Wrap(err, "parsing config file")
	}

	cloud, ok := cfg["cloud"]
	if !ok {
		return errw.New("no cloud section in local config file")
	}

	for _, req := range []string{"app_address", "id", "secret"} {
		field, ok := cloud[req]
		if !ok {
			return errw.Errorf("no cloud config field for %s", field)
		}
	}

	m.cloudAddr = cloud["app_address"]
	m.partID = cloud["id"]
	m.cloudSecret = cloud["secret"]

	return nil
}

var ErrMissingCloudCreds = errors.New("can't create NetAppender without cloud creds")

func (m *Manager) NetAppender(ctx context.Context) (*logging.NetAppender, error) {
	if err := m.dial(ctx); err != nil {
		return nil, err
	}
	if m.cloudAddr == "" || m.partID == "" || m.cloudSecret == "" {
		return nil, ErrMissingCloudCreds
	}
	return logging.NewNetAppender(
		&logging.CloudConfig{
			AppAddress: m.cloudAddr,
			ID:         m.partID,
			Secret:     m.cloudSecret,
		},
		m.conn,
	)
}

// StartSubsystem may be called early in startup when no cloud connectivity is configured.
func (m *Manager) StartSubsystem(ctx context.Context, name string) error {
	m.subsystemsMu.Lock()
	defer m.subsystemsMu.Unlock()

	subsys, ok := m.loadedSubsystems[name]
	if !ok {
		return errw.Errorf("unable to find subsystem %s", name)
	}

	return subsys.Start(ctx)
}

// SelfUpdate is called early in startup to update the viam-agent subsystem before any other work is started.
func (m *Manager) SelfUpdate(ctx context.Context) (bool, error) {
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	m.subsystemsMu.Lock()
	subsys, ok := m.loadedSubsystems[SubsystemName]
	m.subsystemsMu.Unlock()
	if !ok {
		m.logger.Warnf("cannot load %s subsystem", SubsystemName)
	}
	cfgMap, _, err := m.GetConfig(ctx)
	if err != nil {
		return false, err
	}
	cfg, ok := cfgMap[SubsystemName]
	if !ok {
		return false, errw.Errorf("no %s section found in config", SubsystemName)
	}
	return subsys.Update(ctx, cfg)
}

// SubsystemUpdates checks for updates to configured subsystems and restarts them as needed.
func (m *Manager) SubsystemUpdates(ctx context.Context, cfg map[string]*pb.DeviceSubsystemConfig) {
	if ctx.Err() != nil {
		return
	}
	m.subsystemsMu.Lock()
	defer m.subsystemsMu.Unlock()

	// check updates and (re)start
	for name, sub := range m.loadedSubsystems {
		if ctx.Err() != nil {
			return
		}
		cancelCtx, cancel := context.WithTimeout(ctx, time.Minute*5)
		defer cancel()
		restart, err := sub.Update(cancelCtx, cfg[name])
		if err != nil {
			m.logger.Error(err)
			continue
		}
		if restart {
			if err := sub.Stop(ctx); err != nil {
				m.logger.Error(err)
				continue
			}
		}
		if err := sub.Start(ctx); err != nil && !errors.Is(err, ErrSubsystemDisabled) {
			m.logger.Error(err)
		}
	}
}

// CheckUpdates retrieves an updated config from the cloud, and then passes it to SubsystemUpdates().
func (m *Manager) CheckUpdates(ctx context.Context) time.Duration {
	m.logger.Debug("Checking cloud for update")
	cfg, interval, err := m.GetConfig(ctx)

	// randomly fuzz the interval by +/- 5%
	interval = fuzzTime(interval, 0.05)

	if err != nil {
		m.logger.Error(err)
		return interval
	}

	// update and (re)start subsystems
	m.SubsystemUpdates(ctx, cfg)

	return interval
}

// SubsystemHealthChecks makes sure all subsystems are responding, and restarts them if not.
func (m *Manager) SubsystemHealthChecks(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	m.logger.Debug("Starting health checks for all subsystems")
	m.subsystemsMu.Lock()
	defer m.subsystemsMu.Unlock()
	for subsystemName, sub := range m.loadedSubsystems {
		if ctx.Err() != nil {
			return
		}
		ctxTimeout, cancelFunc := context.WithTimeout(ctx, time.Second*15)
		defer cancelFunc()
		if err := sub.HealthCheck(ctxTimeout); err != nil {
			if ctx.Err() != nil {
				return
			}
			m.logger.Error(errw.Wrapf(err, "subsystem healthcheck failed for %s", subsystemName))
			if err := sub.Stop(ctx); err != nil {
				m.logger.Error(errw.Wrapf(err, "stopping subsystem %s", subsystemName))
			}
			if ctx.Err() != nil {
				return
			}
			if err := sub.Start(ctx); err != nil && !errors.Is(err, ErrSubsystemDisabled) {
				m.logger.Error(errw.Wrapf(err, "restarting subsystem %s", subsystemName))
			}
		}
	}
}

// CloseAll stops all subsystems and closes the cloud connection.
func (m *Manager) CloseAll() {
	ctx, cancelFunc := context.WithTimeout(context.Background(), stopAllTimeout)
	defer cancelFunc()

	m.subsystemsMu.Lock()
	defer m.subsystemsMu.Unlock()
	// close all subsystems
	for _, sub := range m.loadedSubsystems {
		if err := sub.Stop(ctx); err != nil {
			m.logger.Error(err)
		}
	}
	m.activeBackgroundWorkers.Wait()

	m.connMu.Lock()
	defer m.connMu.Unlock()

	if m.conn != nil {
		err := m.conn.Close()
		if err != nil {
			m.logger.Error(err)
		}
	}

	m.client = nil
	m.conn = nil
}

// StartBackgroundChecks kicks off a go routine that loops on a timer to check for updates and health checks.
func (m *Manager) StartBackgroundChecks(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	m.logger.Debug("starting background checks")
	m.activeBackgroundWorkers.Add(1)
	go func() {
		checkInterval := m.CheckUpdates(ctx)
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
				checkInterval = m.CheckUpdates(ctx)
				m.SubsystemHealthChecks(ctx)
				timer.Reset(checkInterval)
			}
		}
	}()
}

// LoadSubsystems runs at startup, before getting online.
func (m *Manager) LoadSubsystems(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	m.subsystemsMu.Lock()
	defer m.subsystemsMu.Unlock()

	cachedConfig, err := m.getCachedConfig()
	if err != nil {
		m.logger.Error(errw.Wrap(err, "getting cached config"))
	}

	for _, name := range registry.List() {
		cfg, ok := cachedConfig[name]
		if !ok {
			cfg = registry.GetDefaultConfig(name)
		}
		err := m.loadSubsystem(ctx, name, cfg)
		if err != nil {
			m.logger.Warnw("couldn't load subsystem", "name", name, "error", err)
		}
	}

	return nil
}

// loadSubsystem needs to be called inside a lock.
func (m *Manager) loadSubsystem(ctx context.Context, name string, subCfg *pb.DeviceSubsystemConfig) error {
	creator := registry.GetCreator(name)
	if creator != nil {
		sub, err := creator(ctx, m.logger, subCfg)
		if err != nil {
			return err
		}
		m.loadedSubsystems[name] = sub
		return nil
	}
	return errw.Errorf("unknown subsystem name %s", name)
}

// getCachedConfig returns a cached config, for when the cloud is not reachable.
func (m *Manager) getCachedConfig() (map[string]*pb.DeviceSubsystemConfig, error) {
	// return a bare-minimum for self-update on new installs or for fallback
	cachedConfig := map[string]*pb.DeviceSubsystemConfig{SubsystemName: {}}

	cacheFilePath := filepath.Join(ViamDirs["cache"], agentCachePath)
	//nolint:gosec
	cacheBytes, err := os.ReadFile(cacheFilePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return cachedConfig, nil
		}
		return nil, errw.Wrap(err, "reading cached config")
	}

	err = json.Unmarshal(cacheBytes, &cachedConfig)
	if err != nil {
		return nil, errw.Wrapf(err, "parsing cached config")
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
	//nolint:gosec
	return errors.Join(os.WriteFile(cacheFilePath, cacheData, 0o644), SyncFS(cacheFilePath))
}

// dial establishes a connection to the cloud for grpc communication.
func (m *Manager) dial(ctx context.Context) error {
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

	conn, err := rpc.DialDirectGRPC(ctx, u.Host, m.logger.AsZap(), dialOpts...)
	if err != nil {
		return err
	}
	m.conn = conn
	m.client = pb.NewAgentDeviceServiceClient(m.conn)
	return nil
}

// GetConfig retrieves the configuration from the cloud, or returns a cached version if unable to communicate.
func (m *Manager) GetConfig(ctx context.Context) (map[string]*pb.DeviceSubsystemConfig, time.Duration, error) {
	timeoutCtx, cancelFunc := context.WithTimeout(ctx, defaultNetworkTimeout)
	defer cancelFunc()

	if err := m.dial(timeoutCtx); err != nil {
		m.logger.Error(errw.Wrapf(err, "fetching %s config", SubsystemName))
		conf, err := m.getCachedConfig()
		return conf, minimalCheckInterval, err
	}

	req := &pb.DeviceAgentConfigRequest{
		Id:                m.partID,
		HostInfo:          m.getHostInfo(),
		SubsystemVersions: m.getSubsystemVersions(),
	}
	resp, err := m.client.DeviceAgentConfig(timeoutCtx, req)
	if err != nil {
		m.logger.Error(errw.Wrapf(err, "fetching %s config", SubsystemName))
		conf, err := m.getCachedConfig()
		return conf, minimalCheckInterval, err
	}

	m.logger.Debugf("Cloud-provided config: %+v", resp)

	err = m.saveCachedConfig(resp.GetSubsystemConfigs())
	if err != nil {
		m.logger.Error(errw.Wrap(err, "saving agent config to cache"))
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
