package syscfg

// This file implements agent-managed OS package upgrades.
// Unlike the unattended-upgrades approach (which delegates to a systemd timer),
// managed mode has the agent run apt upgrades directly on a controlled schedule
// and coordinate reboots with viam-server's maintenance window.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/utils"
)

const (
	rebootRequiredPath     = "/var/run/reboot-required"
	defaultUpgradeInterval = 24 * time.Hour
	managedSecurityMode    = "managed-security"
)

// startManagedUpgrades launches the background goroutine that periodically runs apt upgrades.
// Must be called while s.mu is held.
func (s *Subsystem) startManagedUpgrades(ctx context.Context) {
	if s.upgradeCancel != nil {
		return // already running
	}

	interval := time.Duration(float64(time.Hour) * s.cfg.OSManagedUpgradeIntervalHours)
	if interval < time.Hour {
		interval = defaultUpgradeInterval
	}

	upgradeCtx, cancel := context.WithCancel(ctx)
	s.upgradeCancel = cancel

	s.upgradeWorker.Go(func() {
		defer s.upgradeWorker.Done()

		// Run once immediately at startup.
		s.runManagedUpgrade(upgradeCtx)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-upgradeCtx.Done():
				return
			case <-ticker.C:
				s.runManagedUpgrade(upgradeCtx)
			}
		}
	})
}

// stopManagedUpgrades cancels the background upgrade goroutine and waits for it to exit.
// Must be called while s.mu is held.
func (s *Subsystem) stopManagedUpgrades() {
	cancel := s.upgradeCancel
	s.upgradeCancel = nil

	if cancel != nil {
		cancel()
		s.upgradeWorker.Wait()
	}
}

// NeedsOSReboot returns true if a system reboot is pending due to installed package updates.
func (s *Subsystem) NeedsOSReboot() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.needsOSReboot
}

// runManagedUpgrade runs apt-get update and then installs available upgrades.
func (s *Subsystem) runManagedUpgrade(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}

	s.mu.RLock()
	mode := s.cfg.OSAutoUpgradeType
	s.mu.RUnlock()

	s.logger.Info("Running managed OS package update")

	// Ensure the unattended-upgrades package is available (used for security-filtered upgrades).
	if err := verifyInstall(ctx); err != nil {
		if installErr := doInstall(ctx); installErr != nil {
			s.logger.Warnw("failed to install unattended-upgrades package", "error", installErr)
			return
		}
	}

	// Refresh package lists.
	if err := aptCmd(ctx, "apt-get", "update"); err != nil {
		s.logger.Warnw("apt-get update failed", "error", err)
		return
	}

	if mode == managedSecurityMode {
		// For security-only mode, use unattended-upgrade which handles origin filtering correctly.
		if err := s.runSecurityUpgrade(ctx); err != nil {
			s.logger.Warnw("security upgrade failed", "error", err)
			return
		}
	} else {
		// For managed-all mode, run a full upgrade.
		err := aptCmd(ctx, "apt-get", "upgrade", "-y",
			"-o", "Dpkg::Options::=--force-confold",
			"-o", "Dpkg::Options::=--force-confdef",
		)
		if err != nil {
			s.logger.Warnw("apt-get upgrade failed", "error", err)
			return
		}
	}

	s.logger.Info("OS package upgrade completed")

	// Check if a reboot is required.
	if rebootRequired(ctx) {
		s.mu.Lock()
		s.needsOSReboot = true
		s.mu.Unlock()
		s.logger.Info("OS reboot required after package updates, will reboot when maintenance window opens")
	}
}

// runSecurityUpgrade writes a security-only unattended-upgrades config and runs unattended-upgrade.
func (s *Subsystem) runSecurityUpgrade(ctx context.Context) error {
	// Generate and write origins config scoped to security repos only.
	confContents, err := generateOrigins(ctx, true)
	if err != nil {
		return errw.Wrap(err, "generating security origins")
	}

	if _, err := utils.WriteFileIfNew(unattendedUpgradesPath, []byte(confContents)); err != nil {
		return errw.Wrap(err, "writing unattended-upgrades config")
	}

	if _, err := utils.WriteFileIfNew(autoUpgradesPath, []byte(autoUpgradesContentsEnabled)); err != nil {
		return errw.Wrap(err, "writing auto-upgrades config")
	}

	cmd := exec.CommandContext(ctx, "unattended-upgrade", "--verbose")
	cmd.Env = append(os.Environ(),
		"DEBIAN_FRONTEND=noninteractive",
		"APT_LISTCHANGES_FRONTEND=none",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errw.Wrapf(err, "unattended-upgrade: %s", output)
	}
	return nil
}

// rebootRequired checks whether the system needs a reboot after package updates.
// It checks /var/run/reboot-required (Debian/Ubuntu) and falls back to
// `needs-restarting -r` (RHEL/CentOS/Fedora/Rocky/Alma).
func rebootRequired(ctx context.Context) bool {
	// Debian/Ubuntu: apt and needrestart write this file when a reboot is needed.
	if _, err := os.Stat(rebootRequiredPath); err == nil {
		return true
	}

	// RHEL-family: needs-restarting -r exits 1 when a reboot is required, 0 otherwise.
	// Any other non-zero exit (e.g. command not found) is treated as "not required".
	cmd := exec.CommandContext(ctx, "needs-restarting", "-r")
	if err := cmd.Run(); err != nil {
		// ExitError is returned if the command starts but returns non-zero. In the
		// case of `needs-restarting` that means a restart is required. If the
		// command cannot be started a different error type is returned.
		if _, ok := errors.AsType[*exec.ExitError](err); ok {
			return true
		}
	}

	return false
}

// aptCmd runs an apt command with DEBIAN_FRONTEND=noninteractive.
func aptCmd(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w\n%s", name, args, err, output)
	}
	return nil
}
