package agent

import (
	"context"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/edaniels/golog"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	pb "go.viam.com/api/app/agent/v1"
	"go.viam.com/utils/rpc"
)

const (
	defaultCheckInterval = time.Second * 60
	agentCachePath       = "agent_config.json"
)

func (m *Manager) dial(ctx context.Context, logger golog.Logger) error {
	m.mu.Lock()
	defer m.mu.Unlock()
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

func (m *Manager) GetConfig(ctx context.Context, logger *zap.SugaredLogger) (map[string]*pb.DeviceSubsystemConfig, time.Duration, error) {
	err := m.dial(ctx, logger)
	if err != nil {
		logger.Error(errors.Wrap(err, "error fetching viam-agent config"))
		conf, err := m.getCachedConfig()
		return conf, defaultCheckInterval, err
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
		return conf, defaultCheckInterval, err
	}

	err = m.saveCachedConfig(resp.GetSubsystemConfigs())
	if err != nil {
		logger.Error(errors.Wrap(err, "error saving agent config to cache"))
	}

	return resp.GetSubsystemConfigs(), resp.GetCheckInterval().AsDuration(), nil
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
