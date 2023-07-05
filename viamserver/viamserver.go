package viamserver

import (
	"context"
	"os/exec"
	"syscall"

	"github.com/viamrobotics/agent"
	"go.uber.org/zap"
)

const (
	viamDir = "/opt/viam"
)

type viamServer struct {
	cmd    *exec.Cmd
	logger *zap.SugaredLogger
}

func (s viamServer) Start() error {
	s.logger.Info("SMURF START")
	return s.cmd.Start()
}

func (s viamServer) Stop() error {
	s.logger.Info("SMURF STOP")
	if s.cmd.Process == nil {
		return nil
	}
	err := s.cmd.Process.Signal(syscall.SIGTERM)
	if err != nil {
		s.logger.Error(err)
		// TODO nuke it
	}
	return s.cmd.Wait()
}

func (s viamServer) CheckOK(ctx context.Context) bool {
	return true
}

func (s viamServer) Update(ctx context.Context, cfg agent.SubsystemConfig) (bool, error) {
	// TODO
	return true, nil
}

func NewSubsystem(ctx context.Context, updateConf agent.SubsystemConfig, logger *zap.SugaredLogger) agent.Subsystem {
	subSys := &viamServer{}
	subSys.logger = logger.Named("viam-server")
	subSys.cmd = exec.Command("bin/viam-server", "-config", "etc/viam.json")
	subSys.cmd.Dir = viamDir
	subSys.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	subSys.cmd.Stdout = &stdioLogger{subSys.logger}
	subSys.cmd.Stderr = &stderrLogger{subSys.logger}

	return subSys
}

type stdioLogger struct {
	logger *zap.SugaredLogger
}

func (l stdioLogger) Write(p []byte) (n int, err error) {
	l.logger.Info(p)
	return len(p), nil
}

type stderrLogger struct {
	logger *zap.SugaredLogger
}

func (l stderrLogger) Write(p []byte) (n int, err error) {
	l.logger.Error(p)
	return len(p), nil
}
