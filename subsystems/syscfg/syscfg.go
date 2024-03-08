// Package syscfg contains the system configuration agent subsystem.
package syscfg

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
	Debug         = false
	DefaultConfig = &pb.DeviceSubsystemConfig{}
)

const (
	SubsysName = "agent-syscfg"
)

func NewSubsystem(ctx context.Context, logger *zap.SugaredLogger, updateConf *pb.DeviceSubsystemConfig) (subsystems.Subsystem, error) {
	extraArgs := []string{}
	if Debug {
		extraArgs = []string{"--debug"}
	}
	is, err := agent.NewInternalSubsystem(SubsysName, extraArgs, logger)
	if err != nil {
		return nil, err
	}
	return agent.NewAgentSubsystem(ctx, SubsysName, logger, is)
}
