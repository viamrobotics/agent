package agent

import (
	"context"
	"encoding/hex"
	"net/url"
	"time"

	"github.com/Masterminds/semver"
	"github.com/edaniels/golog"
	pb "go.viam.com/api/app/agent/v1"
	"go.viam.com/utils/rpc"
)

var (
	client pb.AgentDeviceServiceClient
	partID string
)

type Config struct {
	UpdateInfo
	SubsystemConfigs map[string]SubsystemConfig
	CheckInterval    time.Duration
}

type UpdateInfo struct {
	Filename string
	URL      string
	Version  *semver.Version
	SHA256   []byte
	Format   Format
}

type SubsystemConfig struct {
	Name string
	UpdateInfo
	Disable      bool
	ForceRestart bool
}

type Format uint8

const (
	// unknown/unset (autodetection may be attempted).
	FormatUnspecified = Format(iota)
	// do nothing.
	FormatRaw
	// decompress .xz file.
	FormatXZ
	// set executable permissions.
	FormatExecutable
	// decompress and set executable.
	FormatXZExecutable
)

// TODO fetch the actual config from the WIP endpoint on App.
func GetTestConfig() Config {
	url := "https://storage.googleapis.com/packages.viam.com/apps/viam-server/viam-server-v0.6.0-x86_64"
	//nolint:errcheck
	// v0.3.0 sha, _ := hex.DecodeString("0f362a74cfcb5e18158af7342ac7a9fc053b75a19065550b111b1756f5631eed")
	sha, _ := hex.DecodeString("12112b05cc50045add9fba432992e0bb283e48659e048dcea1a9ba3d55149195")
	//nolint:errcheck
	version, _ := semver.NewVersion("v0.6.0")

	cfg := Config{
		UpdateInfo: UpdateInfo{
			Filename: "viam-agent",
			URL:      "",
			Version:  nil,
			SHA256:   []byte{},
			Format:   FormatUnspecified,
		},
		SubsystemConfigs: map[string]SubsystemConfig{
			"viam-server": {
				Name: "viam-server",
				UpdateInfo: UpdateInfo{
					Filename: "viam-server",
					URL:      url,
					Version:  version,
					SHA256:   sha,
					Format:   FormatExecutable,
				},
				Disable:      false,
				ForceRestart: false,
			},
		},
		CheckInterval: time.Second * 10,
	}

	return cfg
}

func Dial(ctx context.Context, logger golog.Logger, addr, id, secret string) error {
	u, err := url.Parse(addr)
	if err != nil {
		return err
	}

	dialOpts := make([]rpc.DialOption, 0, 2)
	// Only add credentials when secret is set.
	if secret != "" {
		dialOpts = append(dialOpts, rpc.WithEntityCredentials(id,
			rpc.Credentials{
				Type:    "robot-secret",
				Payload: secret,
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

	client = pb.NewAgentDeviceServiceClient(conn)
	partID = id
	return nil
}

func GetConfig(ctx context.Context) (*Config, error) {
	distro := "arch:unknown"

	resp, err := client.DeviceAgentConfig(ctx, &pb.DeviceAgentConfigRequest{
		Id:           partID,
		AgentVersion: "0.1",
		HostInfo: &pb.HostInfo{
			Platform: "linux/amd64",
			Distro:   &distro,
			Tags:     []string{},
		},
		SubsystemVersions: []*pb.SubsystemVersion{{
			SubsystemName:    "viam-server",
			SubsystemVersion: "0.1.111111",
		}},
	})
	if err != nil {
		return nil, err
	}

	return protoToConfig(resp)
}

func protoToConfig(in *pb.DeviceAgentConfigResponse) (*Config, error) {
	agentVer, err := semver.NewVersion(in.GetUpdateInfo().GetVersion())
	if err != nil {
		return nil, err
	}

	out := &Config{
		UpdateInfo: UpdateInfo{
			Filename: in.GetUpdateInfo().GetFilename(),
			URL:      in.GetUpdateInfo().GetUrl(),
			Version:  agentVer,
			SHA256:   in.GetUpdateInfo().GetSha256(),
			Format:   FormatExecutable,
		},
		SubsystemConfigs: map[string]SubsystemConfig{},
		CheckInterval:    in.GetCheckInterval().AsDuration(),
	}

	for _, subsys := range in.GetSubsystemConfig() {
		ver, err := semver.NewVersion(subsys.GetUpdateInfo().GetVersion())
		if err != nil {
			return nil, err
		}
		out.SubsystemConfigs[subsys.GetSubsystemName()] = SubsystemConfig{
			Disable:      subsys.Disable,
			ForceRestart: subsys.GetForceRestart(),
			UpdateInfo: UpdateInfo{
				Filename: subsys.GetUpdateInfo().GetFilename(),
				URL:      subsys.GetUpdateInfo().GetUrl(),
				Version:  ver,
				SHA256:   subsys.GetUpdateInfo().GetSha256(),
				Format:   FormatExecutable,
			},
		}
	}
	return out, nil
}
