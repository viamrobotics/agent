package syscfg

import (
	"context"

	"github.com/viamrobotics/agent/subsystems"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
)

func NewSubsystem(_ context.Context, _ logging.Logger, _ utils.AgentConfig, _ func() logging.Appender) subsystems.Subsystem {
	return &subsystems.Dummy{}
}
