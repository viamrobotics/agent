//go:build !linux

package syscfg

import (
	"context"

	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
)

// Subsystem is an empty struct with noop methods for unsupported OSes.
type Subsystem struct{}

func New(_ context.Context, _ logging.Logger, _ utils.AgentConfig, _ func() logging.Appender, _ bool) *Subsystem {
	return &Subsystem{}
}

func (s *Subsystem) Start(_ context.Context) error {
	return nil
}

func (s *Subsystem) Stop(_ context.Context) error {
	return nil
}

func (s *Subsystem) Update(_ context.Context, _ utils.AgentConfig) bool {
	return false
}

func (s *Subsystem) HealthCheck(_ context.Context) error {
	return nil
}
