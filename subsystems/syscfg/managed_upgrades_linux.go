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
	"fmt"
	"os"
	"os/exec"
	"slices"
	"time"

	"github.com/samber/lo"
	"github.com/viamrobotics/agent/utils"
)

const defaultUpgradeInterval = 24 * time.Hour

func isManaged(mode string) bool {
	return slices.Contains([]string{utils.OSAutoUpgradeManagedAll, utils.OSAutoUpgradeManagedSecurity}, mode)
}

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
		if ctx.Err() != nil {
			return
		}
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

// detectPackageManager returns an implementation of [packageManager] that
// matches the package manager binaries available on the OS.
func detectPackageManager() (packageManager, error) {
	type pmOption struct {
		binary      string
		constructor func() packageManager
	}
	pms := []pmOption{
		{
			"apt-get",
			func() packageManager { return aptPackageManager{} },
		},
		{
			"dnf",
			func() packageManager { return rpmPackageManager{useDnf: true} },
		},
		{
			"yum",
			func() packageManager { return rpmPackageManager{useDnf: false} },
		},
	}
	for _, pm := range pms {
		if _, err := exec.LookPath(pm.binary); err == nil {
			return pm.constructor(), nil
		}
	}
	return nil, fmt.Errorf(
		"no supported package manager found (%s)",
		lo.Map(pms, func(item pmOption, _ int) string {
			return item.binary
		}))
}

// runManagedUpgrade detects the package manager and installs available upgrades.
func (s *Subsystem) runManagedUpgrade(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}

	if !s.maintenanceAllowed(ctx) {
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
	securityOnly := mode == utils.OSAutoUpgradeManagedSecurity

	if err := pm.runUpgrade(ctx, securityOnly); err != nil {
		s.logger.Warnw("managed OS upgrade failed", "package_manager", pm, "error", err)
		return
	}
	s.logger.Info("OS package upgrade completed")

	// Check if a reboot is required.
	if pm.needsReboot(ctx) {
		s.mu.Lock()
		s.needsOSReboot = true
		s.mu.Unlock()
		s.logger.Info("OS reboot required after package updates, will reboot when maintenance window opens")
	}
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

type packageManager interface {
	fmt.Stringer
	runUpgrade(ctx context.Context, securityOnly bool) error
	needsReboot(ctx context.Context) bool
}
