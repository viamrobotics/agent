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
	"github.com/viamrobotics/agent/utils"
)

// NeedsOSReboot returns true if a system reboot is pending due to installed package updates.
func (s *Subsystem) NeedsOSReboot(ctx context.Context) bool {
	// Refuse while our own install runs; runManagedUpgrade latches needsOSReboot
	// once it completes. Checked ahead of the cached result below, since a reboot
	// can be pending from an earlier cycle while a later one is still installing.
	if s.upgrade.running() {
		return false
	}

	s.mu.RLock()
	needReboot := s.needsOSReboot
	autoUpgradeType := s.cfg.OSAutoUpgradeType
	s.mu.RUnlock()

	// Skipped when already cached; there is no way for a pending reboot to become
	// unnecessary until the reboot happens.
	if !needReboot {
		if !isManaged(autoUpgradeType) {
			// We only care about managing reboots in managed upgrade mode.
			return false
		}

		if !windowsRebootRequired(ctx) {
			return false
		}

		// Cache the first positive result.
		s.mu.Lock()
		s.needsOSReboot = true
		s.mu.Unlock()
	}

	// A reboot is pending; whether it is safe to act on is a separate question. The
	// registry key is set partway through a batch, and we did not necessarily set
	// it — Windows' own Automatic Updates install on their own schedule. Hold off
	// rather than force-reboot an install we know nothing about; we are polled once
	// a minute, so this only delays it.
	blocked := windowsUpdateBusy(ctx)
	s.rebootBlocked.note(s.logger, blocked,
		"OS reboot pending, but Windows servicing is still in progress; waiting for it to finish")

	return !blocked
}

// startManagedUpgrades launches the background goroutine that periodically runs Windows Update.
// Must be called while s.mu is held.
func (s *Subsystem) startManagedUpgrades(ctx context.Context) {
	if s.upgradeCancel != nil {
		return // already running
	}

	interval := clampUpgradeInterval(s.logger, s.cfg.OSManagedUpgradeIntervalHours)
	logManagedUpgradesStarted(s.logger, s.cfg.OSAutoUpgradeType, interval)

	upgradeCtx, cancel := context.WithCancel(ctx)
	s.upgradeCancel = cancel

	s.upgradeWorker.Go(func() {
		// Run once immediately at startup.
		if ctx.Err() != nil {
			return
		}
		var blockedLogged bool
		err := s.runManagedUpgrade(upgradeCtx)
		logIfNewlyBlocked(s.logger, err, &blockedLogged)

		timer := time.NewTimer(nextUpgradeInterval(err, interval))
		defer timer.Stop()
		for {
			select {
			case <-upgradeCtx.Done():
				return
			case <-timer.C:
				err = s.runManagedUpgrade(upgradeCtx)
				logIfNewlyBlocked(s.logger, err, &blockedLogged)
				timer.Reset(nextUpgradeInterval(err, interval))
			}
		}
	})
}

// runManagedUpgrade runs a Windows Update cycle via PSWindowsUpdate.
// It returns errBlockedByMaintenanceWindow if the upgrade could not run because
// viam-server's maintenance window is closed, so the caller can retry sooner
// than the configured interval.
func (s *Subsystem) runManagedUpgrade(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if !s.maintenanceAllowed(ctx) {
		return errBlockedByMaintenanceWindow
	}

	s.mu.RLock()
	mode := s.cfg.OSAutoUpgradeType
	s.mu.RUnlock()

	s.logger.Info("Running managed Windows Update")

	// Block reboots for the duration of the install: Windows sets RebootRequired as
	// soon as one update needs it, so the key can appear while the rest of the batch
	// is still being written to the component store.
	err := func() error {
		defer s.upgrade.begin()()
		return runWindowsUpdate(ctx, mode == utils.OSAutoUpgradeManagedSecurity)
	}()
	if err != nil {
		s.logger.Warnw("Windows Update failed", "error", err)
		return err
	}

	s.logger.Info("Windows Update completed")

	if windowsRebootRequired(ctx) {
		s.mu.Lock()
		s.needsOSReboot = true
		s.mu.Unlock()
		s.logger.Info("OS reboot required after Windows updates, will reboot when maintenance window opens")
	}

	return nil
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

// runWindowsUpdate installs updates via the PSWindowsUpdate PowerShell module.
// Devices already configured to use a WSUS server (via Group Policy or registry) will
// automatically receive updates from that server without any extra configuration.
func runWindowsUpdate(ctx context.Context, securityOnly bool) error {
	// Ensure PSWindowsUpdate is available; Install-Module is a no-op if already present.
	ensureModule := `if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) { ` +
		`Install-PackageProvider -Name NuGet -Force; ` +
		`Install-Module -Name PSWindowsUpdate -Confirm:$False -Force -Scope AllUsers }`
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

// windowsUpdateBusy reports whether servicing is in flight, covering batches the
// agent did not start. Both signals are needed because neither subsumes the
// other: IsBusy sees Windows Update Agent sessions, including MSI- and
// driver-shaped updates that never touch the component store, while
// TrustedInstaller sees component-based servicing from any source (.msu, DISM,
// feature changes) and keeps running after the WUA session that queued it ends.
//
// TrustedInstaller is the blunter of the two, lingering idle for minutes after
// servicing finishes, so it can hold a reboot past the maintenance window and
// into the next one. That beats force-rebooting a transaction we cannot see the
// end of.
func windowsUpdateBusy(ctx context.Context) bool {
	// IsBusy first, so the second process spawn is skipped when WUA is mid-install.
	return updateInstallerBusy(ctx) || trustedInstallerRunning(ctx)
}

// updateInstallerBusy reports IUpdateInstaller.IsBusy, which covers the whole
// machine rather than just our own COM object. Errors read as "not busy" since
// trustedInstallerRunning still runs alongside it.
func updateInstallerBusy(ctx context.Context) bool {
	out, err := exec.CommandContext(ctx, "powershell",
		"-NonInteractive", "-NoProfile",
		"-Command", `(New-Object -ComObject Microsoft.Update.Installer).IsBusy`,
	).Output()
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(string(out)), "True")
}

// trustedInstallerRunning reports whether the Windows Modules Installer service
// is running, which it does for the duration of a servicing transaction. Errors
// read as "not running" so a broken check cannot block reboots forever.
func trustedInstallerRunning(ctx context.Context) bool {
	out, err := exec.CommandContext(ctx, "powershell",
		"-NonInteractive", "-NoProfile",
		"-Command", `(Get-Service -Name TrustedInstaller).Status`,
	).Output()
	if err != nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(string(out)), "Running")
}

// runPowerShell executes a PowerShell command, returning a wrapped error with output on failure.
func runPowerShell(ctx context.Context, script string) error {
	cmd := exec.CommandContext(ctx, "powershell",
		"-NonInteractive", "-NoProfile", "-ExecutionPolicy", "RemoteSigned",
		"-Command", script,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("powershell: %w\n%s", err, output)
	}
	return nil
}
