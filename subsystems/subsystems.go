// Package subsystems defines the subsystem interface.
package subsystems

import (
	"context"

	"github.com/viamrobotics/agent/utils"
)

type Subsystem interface {
	// Start runs the subsystem
	Start(ctx context.Context) error

	// Stop signals the subsystem to shutdown
	Stop(ctx context.Context) error

	// Update validates and/or updates a subsystem, returns true if subsystem should be restarted
	Update(ctx context.Context, cfg utils.AgentConfig) bool

	// HealthCheck reports if a subsystem is running correctly (it is restarted if not)
	HealthCheck(ctx context.Context) error
}
