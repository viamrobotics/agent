package agent

import (
	"context"

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
	return s.Process.Start(context.Background())
}

func (s DefaultSubsystem) Stop() error {
	s.Logger.Info("SMURF STOP")
	return s.Process.Stop()
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
