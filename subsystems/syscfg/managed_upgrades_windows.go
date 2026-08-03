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
	if s.upgrade.running() {
		// An update is installing right now. Rebooting would interrupt Windows
		// servicing mid-transaction, so refuse until it finishes; runManagedUpgrade
		// re-checks and latches needsOSReboot once the install completes. This is
		// checked ahead of the cached result below because a reboot can already be
		// pending from an earlier cycle while a later one is still installing.
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

	// A reboot is pending. Whether it is safe to act on it is a separate question:
	// the registry key is set partway through a batch, and we did not necessarily
	// set it, since Windows' own Automatic Updates install on their own schedule.
	// Hold off while servicing is in flight rather than force-rebooting an install
	// we know nothing about. We are polled once a minute, so this only delays the
	// reboot.
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

	// Block reboots for the duration of the install. Windows sets the
	// RebootRequired key as soon as an individual update needs a reboot, so it can
	// appear while the rest of the batch is still being written to the component
	// store; a forced reboot there can corrupt servicing state.
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

// windowsUpdateBusy reports whether servicing is in flight, by either of two
// signals. Neither subsumes the other, so we take both: IUpdateInstaller.IsBusy
// covers Windows Update Agent install sessions (including MSI- and driver-shaped
// updates that never touch the component store), while TrustedInstaller covers
// component-based servicing from any source — .msu packages, DISM, feature
// changes — and keeps running after the WUA session that queued the work has
// ended. Both cover batches the agent did not start, unlike our in-process flag.
//
// TrustedInstaller is the blunter of the two: the service lingers idle for some
// minutes after servicing finishes, so it can hold a reboot past the maintenance
// window and into the next one. That is the cost of not force-rebooting a
// transaction we cannot see the end of.
//
// If both checks fail to read, we report not busy rather than busy — unlike the
// Linux probe, which treats unreadable lock state as held. A host where
// PowerShell is broken would otherwise never reboot at all.
func windowsUpdateBusy(ctx context.Context) bool {
	// IsBusy first: it is the sharper signal, and short-circuiting skips the
	// second process spawn whenever WUA is mid-install.
	return updateInstallerBusy(ctx) || trustedInstallerRunning(ctx)
}

// updateInstallerBusy reports IUpdateInstaller.IsBusy, which is machine-wide
// rather than scoped to our own COM object. Errors are treated as "not busy"
// because the TrustedInstaller check still runs alongside it.
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
// is running, which it does for the duration of a servicing transaction.
// Errors are treated as "not running" so that a broken check cannot block
// reboots indefinitely.
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
