package syscfg

import (
	"context"
	"os/exec"
	"strings"
	"sync"

	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
)

// KernelLogForwarder handles forwarding kernel logs to the cloud
type KernelLogForwarder struct {
	logger logging.Logger
	cfg    utils.SystemConfiguration
	cmd    *exec.Cmd
	ctx    context.Context
	cancel context.CancelFunc

	// mu protects access to cmd and cfg
	mu sync.RWMutex
}

// NewKernelLogForwarder creates a new kernel log forwarder
func NewKernelLogForwarder(logger logging.Logger, cfg utils.SystemConfiguration) *KernelLogForwarder {
	ctx, cancel := context.WithCancel(context.Background())
	return &KernelLogForwarder{
		logger: logger,
		cfg:    cfg,
		ctx:    ctx,
		cancel: cancel,
	}
}

// Start begins forwarding kernel logs if enabled
func (k *KernelLogForwarder) Start() error {
	k.mu.Lock()
	defer k.mu.Unlock()

	// If forwarding is disabled but we have a running process, stop it
	if !k.cfg.ForwardKernelLogs && k.cmd != nil {
		k.cancel()
		if err := k.cmd.Wait(); err != nil && !strings.Contains(err.Error(), "signal: killed") {
			return errw.Wrap(err, "stopping kernel log forwarding")
		}
		k.cmd = nil
		k.logger.Info("Stopped Kernel logs forwarding")
		return nil
	}

	// If forwarding is disabled or we already have a running process, do nothing
	if !k.cfg.ForwardKernelLogs || k.cmd != nil {
		return nil
	}

	if _, err := exec.LookPath("journalctl"); err != nil {
		k.logger.Error("journalctl not available, kernel log forwarding disabled")
		return nil
	}

	// Start journalctl with JSON output and follow mode
	cmd := exec.Command("journalctl", "-f", "-k", "-o", "json", "-n")
	cmd.Stdout = utils.NewMatchingLogger(k.logger, false, true)
	cmd.Stderr = utils.NewMatchingLogger(k.logger, true, true)

	if err := cmd.Start(); err != nil {
		return errw.Wrap(err, "starting kernel log forwarding")
	}

	k.logger.Info("Started Kernel logs forwarding")
	k.cmd = cmd
	return nil
}

// Stop stops the kernel log forwarding
func (k *KernelLogForwarder) Stop() error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.cmd == nil {
		return nil
	}

	k.cancel()
	if err := k.cmd.Wait(); err != nil && !strings.Contains(err.Error(), "signal: killed") {
		return errw.Wrap(err, "stopping kernel log forwarding")
	}

	k.cmd = nil
	k.logger.Info("Stopped Kernel logs forwarding")
	return nil
}

// Update updates the kernel log forwarding configuration
func (k *KernelLogForwarder) Update(cfg utils.SystemConfiguration) error {
	k.mu.Lock()
	k.cfg = cfg
	k.mu.Unlock()
	return nil
}
