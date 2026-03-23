package syscfg

// This file implements agent-managed OS package upgrades.
// Unlike the unattended-upgrades approach (which delegates to a systemd timer),
// managed mode has the agent run apt upgrades directly on a controlled schedule
// and coordinate reboots with viam-server's maintenance window.
//
// Supported package managers (tried in preference order):
//   - dnf  – Fedora, RHEL 8+, Rocky Linux, AlmaLinux, etc.
//   - apt-get – Debian, Ubuntu, Raspberry Pi OS, etc.
//   - yum  – RHEL 7, CentOS 7

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

// startManagedUpgrades launches the background goroutine that periodically runs upgrades.
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

// detectPackageManager returns the name of the first available package manager binary.
func detectPackageManager() (string, error) {
	pms := []string{"apt-get", "dnf", "yum"}
	for _, pm := range pms {
		if _, err := exec.LookPath(pm); err == nil {
			return pm, nil
		}
	}
	return "", fmt.Errorf("no supported package manager found (%s)", pms)
}

// runManagedUpgrade detects the package manager and installs available upgrades.
func (s *Subsystem) runManagedUpgrade(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}

	s.mu.RLock()
	mode := s.cfg.OSAutoUpgradeType
	s.mu.RUnlock()

	pm, err := detectPackageManager()
	if err != nil {
		s.logger.Warnw("skipping managed OS upgrade", "error", err)
		return
	}

	s.logger.Infow("Running managed OS package update", "package_manager", pm)
	securityOnly := mode == managedSecurityMode

	switch pm {
	case "dnf":
		err = runDnfUpgrade(ctx, securityOnly)
	case "yum":
		err = runYumUpgrade(ctx, securityOnly)
	default: // apt-get
		err = s.runAptUpgrade(ctx, securityOnly)
	}

	if err != nil {
		s.logger.Warnw("managed OS upgrade failed", "package_manager", pm, "error", err)
		return
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

// runAptUpgrade handles upgrades on Debian/Ubuntu systems.
// For security-only mode it delegates to unattended-upgrade for precise origin filtering.
func (s *Subsystem) runAptUpgrade(ctx context.Context, securityOnly bool) error {
	// Ensure the unattended-upgrades binary is available (used for security-filtered upgrades).
	if err := verifyInstall(ctx); err != nil {
		if installErr := doInstall(ctx); installErr != nil {
			return errw.Wrap(installErr, "installing unattended-upgrades package")
		}
	}

	// Refresh package lists.
	if err := pkgCmd(ctx, "apt-get", "update"); err != nil {
		return err
	}

	if securityOnly {
		return s.runAptSecurityUpgrade(ctx)
	}
	return pkgCmd(ctx, "apt-get", "upgrade", "-y",
		"-o", "Dpkg::Options::=--force-confold",
		"-o", "Dpkg::Options::=--force-confdef",
	)
}

// runAptSecurityUpgrade writes a security-only unattended-upgrades config and runs unattended-upgrade.
func (s *Subsystem) runAptSecurityUpgrade(ctx context.Context) error {
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

// runDnfUpgrade handles upgrades on Fedora/RHEL 8+/Rocky/Alma systems.
// The --security flag restricts upgrades to packages with a security advisory.
func runDnfUpgrade(ctx context.Context, securityOnly bool) error {
	args := []string{"upgrade", "-y"}
	if securityOnly {
		args = append(args, "--security")
	}
	return pkgCmd(ctx, "dnf", args...)
}

// runYumUpgrade handles upgrades on RHEL 7/CentOS 7 systems.
// The --security flag requires the yum-plugin-security package to be installed.
func runYumUpgrade(ctx context.Context, securityOnly bool) error {
	args := []string{"update", "-y"}
	if securityOnly {
		args = append(args, "--security")
	}
	return pkgCmd(ctx, "yum", args...)
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
		//nolint: errcheck
		if _, ok := errors.AsType[*exec.ExitError](err); ok {
			return true
		}
	}

	return false
}

// pkgCmd runs a package manager command, setting DEBIAN_FRONTEND=noninteractive
// to suppress interactive prompts on apt-based systems (ignored elsewhere).
func pkgCmd(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w\n%s", name, args, err, output)
	}
	return nil
}
