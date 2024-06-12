// Package syscfg contains the system configuration agent subsystem.
package syscfg

import (
	"context"

	"github.com/viamrobotics/agent"
	"github.com/viamrobotics/agent/subsystems"
	"github.com/viamrobotics/agent/subsystems/registry"
	pb "go.viam.com/api/app/agent/v1"
	"go.viam.com/rdk/logging"
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

func NewSubsystem(ctx context.Context, logger logging.Logger, updateConf *pb.DeviceSubsystemConfig) (subsystems.Subsystem, error) {
	extraArgs := []string{}
	if Debug {
		extraArgs = []string{"--debug"}
	}
	is, err := agent.NewInternalSubsystem(SubsysName, extraArgs, logger, true)
	if err != nil {
		return nil, err
	}
	return agent.NewAgentSubsystem(ctx, SubsysName, logger, is)
}
