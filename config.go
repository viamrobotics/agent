package agent

import (
	"context"
	"encoding/hex"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/edaniels/golog"
	"github.com/viamrobotics/agent/subsystems"
	pb "go.viam.com/api/app/agent/v1"
	"go.viam.com/utils/rpc"
)

var (
	client               pb.AgentDeviceServiceClient
	partID               string
	defaultCheckInterval = time.Second * 60

	// mutex protected.
	subsystemsMu     sync.Mutex
	loadedSubsystems = map[string]subsystems.Subsystem{}
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
	req := &pb.DeviceAgentConfigRequest{
		Id:                partID,
		HostInfo:          getHostInfo(),
		SubsystemVersions: getSubsystemVersions(),
	}
	resp, err := client.DeviceAgentConfig(ctx, req)
	if err != nil {
		return nil, defaultCheckInterval, err
	}

	return resp.GetSubsystemConfigs(), resp.GetCheckInterval().AsDuration(), nil
}

func GetTestConfig() (map[string]*pb.DeviceSubsystemConfig, time.Duration, error) {
	url := "https://storage.googleapis.com/packages.viam.com/apps/viam-server/viam-server-v0.6.0-x86_64"
	//nolint:errcheck
	// v0.3.0 sha, _ := hex.DecodeString("0f362a74cfcb5e18158af7342ac7a9fc053b75a19065550b111b1756f5631eed")
	sha, _ := hex.DecodeString("12112b05cc50045add9fba432992e0bb283e48659e048dcea1a9ba3d55149195")
	

	cfgs := map[string]*pb.DeviceSubsystemConfig{
		"viam-agent": {},
		"viam-server": {
			UpdateInfo: &pb.SubsystemUpdateInfo{
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

func getHostInfo() *pb.HostInfo {
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

func getSubsystemVersions() map[string]string {
	vers := map[string]string{}
	return vers
}
