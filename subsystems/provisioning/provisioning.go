// Package provisioning contains the provisioning agent subsystem.
package provisioning

import (
	"context"

	"github.com/viamrobotics/agent"
	"github.com/viamrobotics/agent/subsystems"
	"github.com/viamrobotics/agent/subsystems/registry"
	"go.uber.org/zap"
	pb "go.viam.com/api/app/agent/v1"
)

func init() {
	registry.Register(SubsysName, NewSubsystem, DefaultConfig)
}

var (
	Debug             = false
	DefaultConfig     = &pb.DeviceSubsystemConfig{}
	AppConfigFilePath = "/etc/viam.json"
)

const (
	SubsysName = "agent-provisioning"
)

func NewSubsystem(ctx context.Context, logger *zap.SugaredLogger, updateConf *pb.DeviceSubsystemConfig) (subsystems.Subsystem, error) {
	extraArgs := []string{
		"--app-config", AppConfigFilePath,
		"--provisioning-config", "/etc/viam-provisioning.json",
	}
	if Debug {
		extraArgs = append(extraArgs, "--debug")
	}
	is, err := agent.NewInternalSubsystem(SubsysName, extraArgs, logger)
	if err != nil {
		return nil, err
	}
	return agent.NewAgentSubsystem(ctx, SubsysName, logger, is)
}
