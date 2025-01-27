// Package agent contains the public interfaces, functions, consts, and vars for the viam-server agent.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	errw "github.com/pkg/errors"
	"github.com/tidwall/jsonc"
	"github.com/viamrobotics/agent/subsystems"
	"github.com/viamrobotics/agent/subsystems/networking"
	"github.com/viamrobotics/agent/subsystems/syscfg"
	"github.com/viamrobotics/agent/subsystems/viamserver"
	"github.com/viamrobotics/agent/utils"
	pb "go.viam.com/api/app/agent/v1"
	"go.viam.com/rdk/logging"
	"go.viam.com/utils/rpc"
)

const (
	minimalCheckInterval  = time.Second * 5
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
	cloudConfig *logging.CloudConfig

	logger      logging.Logger
	netAppender *logging.NetAppender

	cfgMu sync.RWMutex
	cfg   utils.AgentConfig

	// also guarded by cfgMu
	viamServerNeedsRestart bool

	viamServer subsystems.Subsystem
	networking subsystems.Subsystem
	sysConfig  subsystems.Subsystem

	cache *VersionCache
}

// NewManager returns a new Manager.
func NewManager(ctx context.Context, logger logging.Logger, cfg utils.AgentConfig) *Manager {
	manager := &Manager{
		logger: logger,
		cfg:    cfg,

		viamServer: viamserver.NewSubsystem(ctx, logger, cfg),
		networking: networking.NewSubsystem(ctx, logger, cfg),
		sysConfig:  syscfg.NewSubsystem(ctx, logger, cfg),
		cache:      NewVersionCache(logger),
	}

	return manager
}

func (m *Manager) LoadAppConfig() error {
	m.connMu.Lock()
	defer m.connMu.Unlock()

	m.logger.Debugf("loading config: %s", utils.AppConfigFilePath)

	b, err := os.ReadFile(utils.AppConfigFilePath)
	if err != nil {
		return errw.Wrap(err, "reading config file")
	}

	cfg := make(map[string]map[string]string)
	err = json.Unmarshal(jsonc.ToJSON(b), &cfg)
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

	m.cloudConfig = &logging.CloudConfig{
		AppAddress: cloud["app_address"],
		ID:         cloud["id"],
		Secret:     cloud["secret"],
	}

	return nil
}

// CreateNetAppender creates or replaces m.netAppender. Must be called after config is loaded.
func (m *Manager) CreateNetAppender() (*logging.NetAppender, error) {
	if m.cloudConfig == nil {
		return nil, errors.New("can't create NetAppender before config has been loaded")
	}
	if m.netAppender != nil {
		m.logger.Warn("m.netAppender already exists, replacing")
	}
	var err error
	m.netAppender, err = logging.NewNetAppender(m.cloudConfig, nil, true, m.logger)
	return m.netAppender, err
}

// StartSubsystem may be called early in startup when no cloud connectivity is configured.
func (m *Manager) StartSubsystem(ctx context.Context, name string) error {
	defer m.handlePanic()

	switch name {
	case viamserver.SubsysName:
		return m.viamServer.Start(ctx)
	case networking.SubsysName:
		return m.networking.Start(ctx)
	case syscfg.SubsysName:
		return m.sysConfig.Start(ctx)
	default:
		return errw.Errorf("unknown subsystem: %s", name)
	}
}

// SelfUpdate is called early in startup to update the viam-agent subsystem before any other work is started.
func (m *Manager) SelfUpdate(ctx context.Context) (bool, error) {
	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	_, err := m.GetConfig(ctx)
	if err != nil {
		return false, err
	}

	needRestart, err := m.cache.UpdateBinary(ctx, SubsystemName)
	if err != nil {
		return false, err
	}

	if needRestart {
		return InstallNewVersion(ctx, m.logger)
	}
	return false, err
}

// SubsystemUpdates checks for updates to configured subsystems and restarts them as needed.
func (m *Manager) SubsystemUpdates(ctx context.Context) {
	defer m.handlePanic()
	if ctx.Err() != nil {
		return
	}

	m.cfgMu.Lock()
	defer m.cfgMu.Unlock()

	// Agent
	needRestart, err := m.cache.UpdateBinary(ctx, SubsystemName)
	if err != nil {
		m.logger.Error(err)
	}
	if needRestart {
		m.logger.Info("viam-agent update complete, please restart using 'systemctl restart viam-agent'")
	}

	// Viam Server
	if m.cfg.AdvancedSettings.DisableViamServer {
		if err := m.viamServer.Stop(ctx); err != nil {
			m.logger.Error(err)
		}
	} else {
		needRestart, err := m.cache.UpdateBinary(ctx, viamserver.SubsysName)
		if err != nil {
			m.logger.Error(err)
		}
		m.viamServer.Update(ctx, m.cfg)

		if needRestart || m.viamServerNeedsRestart {
			if m.viamServer.(viamserver.RestartCheck).SafeToRestart(ctx) {
				if err := m.viamServer.Stop(ctx); err != nil {
					m.logger.Error(err)
				} else {
					m.viamServerNeedsRestart = false
				}
			} else {
				m.viamServerNeedsRestart = true
			}
		}
		if err := m.viamServer.Start(ctx); err != nil {
			m.logger.Error(err)
		}
	}

	// System Configuration
	if m.cfg.AdvancedSettings.DisableSystemConfiguration {
		if err := m.sysConfig.Stop(ctx); err != nil {
			m.logger.Error(err)
		}
	} else {
		needRestart = m.sysConfig.Update(ctx, m.cfg)
		if needRestart {
			if err := m.sysConfig.Stop(ctx); err != nil {
				m.logger.Error(err)
			}
		}
		if err := m.sysConfig.Start(ctx); err != nil {
			m.logger.Error(err)
		}
	}

	// Network
	if m.cfg.AdvancedSettings.DisableNetworkConfiguration {
		if err := m.networking.Stop(ctx); err != nil {
			m.logger.Error(err)
		}
	} else {
		needRestart = m.networking.Update(ctx, m.cfg)
		if needRestart {
			if err := m.networking.Stop(ctx); err != nil {
				m.logger.Error(err)
			}
		}
		if err := m.networking.Start(ctx); err != nil {
			m.logger.Error(err)
		}
	}
}

// CheckUpdates retrieves an updated config from the cloud, and then passes it to SubsystemUpdates().
func (m *Manager) CheckUpdates(ctx context.Context) time.Duration {
	defer m.handlePanic()
	m.logger.Debug("Checking cloud for update")
	interval, err := m.GetConfig(ctx)

	if interval < minimalCheckInterval {
		interval = minimalCheckInterval
	}

	m.cfgMu.RLock()
	if m.cfg.AdvancedSettings.Debug {
		m.logger.SetLevel(logging.DEBUG)
	} else {
		m.logger.SetLevel(logging.INFO)
	}
	m.cfgMu.RUnlock()

	// randomly fuzz the interval by +/- 5%
	interval = utils.FuzzTime(interval, 0.05)

	if err != nil {
		m.logger.Error(err)
		return interval
	}

	// update and (re)start subsystems
	m.SubsystemUpdates(ctx)

	return interval
}

// SubsystemHealthChecks makes sure all subsystems are responding, and restarts them if not.
func (m *Manager) SubsystemHealthChecks(ctx context.Context) {
	defer m.handlePanic()
	if ctx.Err() != nil {
		return
	}
	m.logger.Debug("Starting health checks for all subsystems")

	m.cfgMu.RLock()
	defer m.cfgMu.RUnlock()

	for subsystemName, sub := range map[string]subsystems.Subsystem{
		"viam-server": m.viamServer,
		"sysconfig":   m.sysConfig,
		"networking":  m.networking,
	} {
		if ctx.Err() != nil {
			return
		}

		switch subsystemName {
		case "viam-server":
			if m.cfg.AdvancedSettings.DisableViamServer {
				return
			}
		case "sysconfig":
			if m.cfg.AdvancedSettings.DisableSystemConfiguration {
				return
			}
		case "networking":
			if m.cfg.AdvancedSettings.DisableNetworkConfiguration {
				return
			}
		}

		ctxTimeout, cancelFunc := context.WithTimeout(ctx, time.Second*15)
		defer cancelFunc()
		if err := sub.HealthCheck(ctxTimeout); err != nil {
			if ctx.Err() != nil {
				return
			}
			m.logger.Error(errw.Wrapf(err, "Subsystem healthcheck failed for %s", subsystemName))
			if err := sub.Stop(ctx); err != nil {
				m.logger.Error(errw.Wrapf(err, "stopping subsystem %s", subsystemName))
			}
			if ctx.Err() != nil {
				return
			}

			if err := sub.Start(ctx); err != nil && !errors.Is(err, utils.ErrSubsystemDisabled) {
				m.logger.Error(errw.Wrapf(err, "restarting subsystem %s", subsystemName))
			}
		} else {
			m.logger.Debugf("Subsystem healthcheck succeeded for %s", subsystemName)
		}
	}
}

// CloseAll stops all subsystems and closes the cloud connection.
func (m *Manager) CloseAll() {
	ctx, cancelFunc := context.WithTimeout(context.Background(), stopAllTimeout)
	defer cancelFunc()

	// close all subsystems
	for _, sub := range []subsystems.Subsystem{m.viamServer, m.sysConfig, m.networking} {
		if err := sub.Stop(ctx); err != nil {
			m.logger.Error(err)
		}
	}
	m.activeBackgroundWorkers.Wait()

	m.connMu.Lock()
	defer m.connMu.Unlock()

	if m.netAppender != nil {
		m.netAppender.Close()
		m.netAppender = nil
	}

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
		checkInterval := minimalCheckInterval
		m.cfgMu.RLock()
		wait := m.cfg.AdvancedSettings.WaitForUpdateCheck
		m.cfgMu.RUnlock()
		if wait {
			checkInterval = m.CheckUpdates(ctx)
		}

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

// dial establishes a connection to the cloud for grpc communication.
// If the dial succeeds, a NetAppender will be attached to m.logger.
func (m *Manager) dial(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if m.cloudConfig == nil {
		return errors.New("cannot dial() until successful LoadConfig")
	}
	m.connMu.Lock()
	defer m.connMu.Unlock()
	if m.client != nil {
		return nil
	}

	u, err := url.Parse(m.cloudConfig.AppAddress)
	if err != nil {
		return err
	}

	dialOpts := make([]rpc.DialOption, 0, 2)
	// Only add credentials when secret is set.
	if m.cloudConfig.Secret != "" {
		dialOpts = append(dialOpts, rpc.WithEntityCredentials(m.cloudConfig.ID,
			rpc.Credentials{
				Type:    "robot-secret",
				Payload: m.cloudConfig.Secret,
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

	if m.netAppender != nil {
		m.netAppender.SetConn(conn, true)
	} else {
		m.logger.Warnf("unintialized NetAppender in dial() -- agent logs won't be uploaded")
	}
	return nil
}

// GetConfig retrieves the configuration from the cloud.
func (m *Manager) GetConfig(ctx context.Context) (time.Duration, error) {
	if m.cloudConfig == nil {
		return minimalCheckInterval, errors.New("can't GetConfig until successful LoadConfig")
	}
	timeoutCtx, cancelFunc := context.WithTimeout(ctx, defaultNetworkTimeout)
	defer cancelFunc()

	if err := m.dial(timeoutCtx); err != nil {
		m.logger.Error(errw.Wrapf(err, "fetching %s config", SubsystemName))
		return minimalCheckInterval, err
	}

	req := &pb.DeviceAgentConfigRequest{
		Id:          m.cloudConfig.ID,
		HostInfo:    m.getHostInfo(),
		VersionInfo: m.getVersions(),
	}
	resp, err := m.client.DeviceAgentConfig(timeoutCtx, req)
	if err != nil {
		m.logger.Error(errw.Wrapf(err, "fetching %s config", SubsystemName))
		return minimalCheckInterval, err
	}

	cfg, err := utils.StackConfigs(resp)
	if err != nil {
		m.logger.Error(errw.Wrap(err, "processing config"))
	}

	if err := utils.SaveConfigToCache(cfg); err != nil {
		m.logger.Error(err)
	}

	cfg = utils.ApplyCLIArgs(cfg)

	m.cfgMu.Lock()
	defer m.cfgMu.Unlock()
	m.cfg = cfg

	return resp.GetCheckInterval().AsDuration(), nil
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

func (m *Manager) getVersions() *pb.VersionInfo {
	m.cfgMu.RLock()
	defer m.cfgMu.RUnlock()
	vers := &pb.VersionInfo{
		AgentRunning:        Version,
		AgentInstalled:      m.cache.AgentVersion(),
		ViamServerRunning:   m.cache.ViamServerVersion(),
		ViamServerInstalled: m.cache.ViamServerVersion(),
	}

	if m.viamServerNeedsRestart {
		vers.ViamServerRunning = m.cache.ViamServerPreviousVersion()
	}

	return vers
}

func (m *Manager) handlePanic() {
	// if something panicked, log it and let things continue
	r := recover()
	if r != nil {
		m.logger.Error("unknown panic encountered, will attempt to recover")
		m.logger.Errorf("panic: %s\n%s", r, debug.Stack())
	}
}
