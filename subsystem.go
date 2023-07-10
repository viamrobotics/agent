// Package agent contains the public interfaces, functions, consts, and vars for the viam-server agent.
package agent

import (
	"context"

	"github.com/pkg/errors"
	"go.uber.org/zap"
	"go.viam.com/utils/pexec"
)

type Subsystem interface {
	// Start runs the subsystem
	Start() error

	// Stop signals the subsystem to shutdown
	Stop() error

	// Update validates and/or updates a subsystem, returns true if subsystem should be restarted
	Update(context.Context, SubsystemConfig) (bool, error)

	// CheckOK reports if a subsystem is running correctly (it is restarted if not)
	CheckOK(context.Context) bool
}

type DefaultSubsystem struct {
	CommonUpdateSubsystem
	AlwaysOKSubsystem
	Process pexec.ManagedProcess
	Logger  *zap.SugaredLogger
}

func (s DefaultSubsystem) Start() error {
	s.Logger.Info("SMURF START")
	return errors.Wrap(s.Process.Start(context.Background()), "default start")
}

func (s DefaultSubsystem) Stop() error {
	s.Logger.Info("SMURF STOP")
	return errors.Wrap(s.Process.Stop(), "default stop")
}

type AlwaysOKSubsystem struct{}

func (s AlwaysOKSubsystem) CheckOK(ctx context.Context) bool {
	return true
}

type CommonUpdateSubsystem struct{}

func (s CommonUpdateSubsystem) Update(ctx context.Context, cfg SubsystemConfig) (bool, error) {
	// TODO
	return true, nil
}
