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

	// Property gets an arbitrary property about the running subystem.
	Property(ctx context.Context, property string) bool
}

// Dummy is a fake subsystem for when a particular OS doesn't (yet) have support.
type Dummy struct{}

func (d *Dummy) Start(_ context.Context) error {
	return nil
}

func (d *Dummy) Stop(_ context.Context) error {
	return nil
}

func (d *Dummy) Update(_ context.Context, _ utils.AgentConfig) bool {
	return false
}

func (d *Dummy) HealthCheck(_ context.Context) error {
	return nil
}

func (d *Dummy) Property(_ context.Context, _ string) bool {
	return false
}
