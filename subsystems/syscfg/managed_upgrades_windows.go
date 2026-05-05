//go:build windows

package syscfg

// This file implements agent-managed OS package upgrades on Windows.
// Updates are installed via the PSWindowsUpdate PowerShell module, which natively
// honours any configured WSUS server (set via Group Policy or registry).
//
// Security-only mode restricts upgrades to the "Security Updates" classification.

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	errw "github.com/pkg/errors"
)

const (
	defaultUpgradeInterval = 24 * time.Hour
	managedSecurityMode    = "managed-security"
)

// NeedsOSReboot returns true if a system reboot is pending due to installed package updates.
func (s *Subsystem) NeedsOSReboot() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.needsOSReboot
}

// startManagedUpgrades launches the background goroutine that periodically runs Windows Update.
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

// runManagedUpgrade runs a Windows Update cycle via PSWindowsUpdate.
func (s *Subsystem) runManagedUpgrade(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}

	s.mu.RLock()
	mode := s.cfg.OSAutoUpgradeType
	s.mu.RUnlock()

	s.logger.Info("Running managed Windows Update check")

	if err := runWindowsUpdate(ctx, mode == managedSecurityMode); err != nil {
		s.logger.Warnw("Windows Update failed", "error", err)
		return
	}

	s.logger.Info("Windows Update completed")

	if windowsRebootRequired(ctx) {
		s.mu.Lock()
		s.needsOSReboot = true
		s.mu.Unlock()
		s.logger.Info("OS reboot required after Windows updates, will reboot when maintenance window opens")
	}
}

// runWindowsUpdate installs updates via the PSWindowsUpdate PowerShell module.
// Devices already configured to use a WSUS server (via Group Policy or registry) will
// automatically receive updates from that server without any extra configuration.
func runWindowsUpdate(ctx context.Context, securityOnly bool) error {
	// Ensure PSWindowsUpdate is available; Install-Module is a no-op if already present.
	ensureModule := `if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) { ` +
		`Install-Module -Name PSWindowsUpdate -Force -Scope AllUsers }`
	if err := runPowerShell(ctx, ensureModule); err != nil {
		return errw.Wrap(err, "ensuring PSWindowsUpdate module")
	}

	// Build the update command. -IgnoreReboot prevents PSWindowsUpdate from rebooting
	// immediately; the agent coordinates the reboot via the maintenance window.
	cmd := "Import-Module PSWindowsUpdate; Get-WindowsUpdate -Install -AcceptAll -IgnoreReboot"
	if securityOnly {
		cmd += " -Category 'Security Updates'"
	}
	if err := runPowerShell(ctx, cmd); err != nil {
		return errw.Wrap(err, "installing Windows updates")
	}
	return nil
}

// windowsRebootRequired checks the Windows Update registry key that signals a pending reboot.
func windowsRebootRequired(ctx context.Context) bool {
	const key = `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`
	//nolint: gosec
	out, err := exec.CommandContext(ctx, "powershell",
		"-NonInteractive", "-NoProfile",
		"-Command", fmt.Sprintf(`Test-Path "%s"`, key),
	).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "True"
}

// runPowerShell executes a PowerShell command, returning a wrapped error with output on failure.
func runPowerShell(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, "powershell",
		"-NonInteractive", "-NoProfile",
		"-Command", script,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("powershell: %w\n%s", err, output)
	}
	return nil
}
