// Package viamserver contains the viam-server agent subsystem.
package viamserver

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"sync"
	"syscall"

	"github.com/pkg/errors"
	"github.com/viamrobotics/agent"
	"go.uber.org/zap"
)

type viamServer struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	running bool

	logger *zap.SugaredLogger
}

func (s *viamServer) Start() error {
	s.logger.Info("SMURF START")
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running == true {
		return nil
	}

	err := s.cmd.Start()
	if err != nil {
		return errors.Wrap(err, "starting viam-server")
	}
	s.logger.Info("SMURF STARTED")
	s.running = true
	return nil
}

func (s *viamServer) Stop() error {
	s.logger.Info("SMURF STOP")
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running || s.cmd.Process == nil {
		return nil
	}
	err := s.cmd.Process.Signal(syscall.SIGTERM)
	if err != nil {
		s.logger.Error(err)
		// TODO nuke it
	}

	err = s.cmd.Wait()
	if err != nil {
		errors.Wrap(err, "stopping viam-server")
	}
	s.running = false
	return nil
}

func (s *viamServer) CheckOK(ctx context.Context) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return true
}

func (s *viamServer) Update(ctx context.Context, cfg agent.SubsystemConfig) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	shasum, err := agent.GetFileSum(path.Join(agent.ViamDir, "bin", cfg.Filename))
	if err == nil && bytes.Equal(shasum, cfg.SHA256) {
		return false, nil
	}

	tempfile, err := agent.DownloadFile(cfg.URL)
	if err != nil {
		return false, errors.Wrap(err, "downloading in viam-server subsystem")
	}
	defer func() {
		if err := os.Remove(tempfile); err != nil && !os.IsNotExist(err) {
			s.logger.Error(err)
		}
	}()

	extractedfile := tempfile
	if cfg.Format == agent.FormatXZ || cfg.Format == agent.FormatXZExecutable {
		extractedfile, err = agent.DecompressFile(tempfile)
		if err != nil {
			return false, errors.Wrap(err, "decompressing in viam-server subsystem")
		}
		defer func() {
			if err := os.Remove(extractedfile); err != nil && !os.IsNotExist(err) {
				s.logger.Error(err)
			}
		}()
	}

	shasum, err = agent.GetFileSum(path.Join(agent.ViamDir, "bin", cfg.Filename))
	if !bytes.Equal(shasum, cfg.SHA256) {
		return false, fmt.Errorf("sha256 of downloaded file (%x) does not match config (%x)", shasum, cfg.SHA256)
	}

	if cfg.Format == agent.FormatExecutable || cfg.Format == agent.FormatXZExecutable {
		if err := os.Chmod(extractedfile, 0o755); err != nil {
			return false, err
		}
	} else {
		if err := os.Chmod(extractedfile, 0o644); err != nil {
			return false, err
		}
	}

	os.MkdirAll(path.Join(agent.ViamDir, "bin"), 0o755)
	os.Rename(tempfile, path.Join(agent.ViamDir, "bin", cfg.Filename))

	return true, nil
}

func NewSubsystem(ctx context.Context, updateConf agent.SubsystemConfig, logger *zap.SugaredLogger) *viamServer {
	subSys := &viamServer{}
	subSys.logger = logger.Named("viam-server")
	subSys.cmd = exec.Command(path.Join("bin", "viam-server"), "-config", path.Join("etc", "viam.json"))
	subSys.cmd.Dir = agent.ViamDir
	subSys.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	subSys.cmd.Stdout = &stdioLogger{subSys.logger}
	subSys.cmd.Stderr = &stderrLogger{subSys.logger}

	return subSys
}

type stdioLogger struct {
	logger *zap.SugaredLogger
}

func (l stdioLogger) Write(p []byte) (int, error) {
	l.logger.Info(string(p))
	return len(p), nil
}

type stderrLogger struct {
	logger *zap.SugaredLogger
}

func (l stderrLogger) Write(p []byte) (int, error) {
	l.logger.Error(string(p))
	return len(p), nil
}
