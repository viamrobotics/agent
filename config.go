package agent

import (
	"context"
	"encoding/hex"
	"net/url"
	"time"

	"github.com/edaniels/golog"
	pb "go.viam.com/api/app/agent/v1"
	"go.viam.com/utils/rpc"
)

var (
	client pb.AgentDeviceServiceClient
	partID string
	defaultCheckInterval = time.Second * 60
)



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

func GetConfig(ctx context.Context) (map[string]*pb.DeviceSubsystemConfig, time.Duration, error) {
	// SMURF TODO get actual platform and versions

	req := &pb.DeviceAgentConfigRequest{
		Id:           partID,
		HostInfo: &pb.HostInfo{
			Platform: "linux/amd64",
			Distro:   "arch:unknown",
			Tags:     []string{},
		},
		SubsystemVersions: map[string]string{
			"agent": "0.1.2222",
			"viam-server": "0.1.1111",
		},
	}


	resp, err := client.DeviceAgentConfig(ctx, req)
	if err != nil {
		return nil, defaultCheckInterval, err
	}

	return resp.SubsystemConfigs, resp.CheckInterval.AsDuration(), nil
}

func GetTestConfig() (map[string]*pb.DeviceSubsystemConfig, time.Duration, error) {
	url := "https://storage.googleapis.com/packages.viam.com/apps/viam-server/viam-server-v0.6.0-x86_64"
	//nolint:errcheck
	// v0.3.0 sha, _ := hex.DecodeString("0f362a74cfcb5e18158af7342ac7a9fc053b75a19065550b111b1756f5631eed")
	sha, _ := hex.DecodeString("12112b05cc50045add9fba432992e0bb283e48659e048dcea1a9ba3d55149195")
	//nolint:errcheck

	cfgs := map[string]*pb.DeviceSubsystemConfig{
		"agent": &pb.DeviceSubsystemConfig{},
		"viam-server": &pb.DeviceSubsystemConfig{
			UpdateInfo:   &pb.SubsystemUpdateInfo{
				Filename: "viam-server",
				Url:      url,
				Version:  "0.6.0",
				Sha256:   sha,
				Format:   pb.PackageFormat_PACKAGE_FORMAT_EXECUTABLE,
			},
			Disable:      false,
			ForceRestart: false,
		},
	}

	return cfgs, defaultCheckInterval, nil
}