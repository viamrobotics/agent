//go:build windows

package syscfg

// This file implements agent-managed OS package upgrades on Windows.
// Updates are installed via the PSWindowsUpdate PowerShell module, which natively
// honours any configured WSUS server (set via Group Policy or registry).
//
// Security-only mode restricts upgrades to the "Security Updates" classification.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	errw "github.com/pkg/errors"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
)

// NeedsOSReboot reports whether a reboot is pending from installed updates and can
// be taken now. Servicing in flight defers it, not cancels it: the answer flips
// back to true once that finishes.
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

	securityOnly := mode == utils.OSAutoUpgradeManagedSecurity
	s.logger.Infow("Running managed Windows Update",
		"os_auto_upgrade_type", mode,
		"security_only", securityOnly,
	)

	// Block reboots for the duration of the upgrade cycle: Windows sets
	// RebootRequired as soon as one update needs it, so the key can appear while
	// the rest of the batch is still being written to the component store.
	upgradeDone := s.upgrade.begin()
	defer upgradeDone()

	if err := ensurePSWindowsUpdate(ctx, s.logger); err != nil {
		s.logger.Errorw("Could not prepare PSWindowsUpdate module, skipping Windows Update", "err", err)
		return err
	}

	pending, listErr := pendingWindowsUpdates(ctx, s.logger, securityOnly)
	updates := updateSummary{updates: pending, listErr: listErr}
	logPendingUpdates(s.logger, updates, "security_only", securityOnly)

	installed, upgradeErr := installWindowsUpdates(ctx, s.logger, securityOnly)
	result := updateSummary{updates: installed}
	if len(installed) == 0 {
		// The install failed, or Windows Update didn't say what it covered. Report what
		// we set out to install rather than an empty list.
		result = updates
	}
	logUpgradeResult(ctx, s.logger, result, upgradeErr, "security_only", securityOnly)
	if upgradeErr != nil {
		return upgradeErr
	}

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

// securityCategory restricts PSWindowsUpdate to security updates only.
const securityCategory = " -Category 'Security Updates'"

// ensurePSWindowsUpdate makes sure the PSWindowsUpdate module is installed.
// Install-Module is a no-op if the module is already present.
func ensurePSWindowsUpdate(ctx context.Context, logger logging.Logger) error {
	ensureModule := `if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) { ` +
		`Install-PackageProvider -Name NuGet -Force; ` +
		`Install-Module -Name PSWindowsUpdate -Confirm:$False -Force -Scope AllUsers }`
	if _, err := runPowerShell(ctx, logger, ensureModule); err != nil {
		return errw.Wrap(err, "ensuring PSWindowsUpdate module")
	}
	return nil
}

// windowsUpdateInfo is one update as reported by Get-WindowsUpdate.
type windowsUpdateInfo struct {
	Title string `json:"title"`
	KB    string `json:"kb"`
	// DownloadSize is the update's MaxDownloadSize in bytes. Windows Update reports
	// no unpacked size.
	DownloadSize uint64 `json:"downloadSize"`
	// Size is PSWindowsUpdate's preformatted size, e.g. "108MB", used as a fallback
	// for older module versions that don't surface MaxDownloadSize.
	Size string `json:"size"`
	// Categories classify the update, e.g. "Security Updates", "Drivers".
	Categories []string `json:"categories"`
	// Result is the install stage an update has reached, e.g. "Accepted",
	// "Downloaded", "Installed" or "Failed". Search results leave it empty.
	Result string `json:"result"`
}

// windowsUpdatesJSON renders a PowerShell snippet that prints the updates held in
// the passed variable as JSON, which is all the snippets that use it write to
// standard output. ConvertTo-Json is fed the array explicitly because piping to it
// would unroll a single update back into an object.
func windowsUpdatesJSON(variable string) string {
	return `ConvertTo-Json -Compress -Depth 3 -InputObject @(` +
		variable + ` | ForEach-Object { [PSCustomObject]@{ title = [string]$_.Title; kb = [string]$_.KB; ` +
		`downloadSize = [uint64]$_.MaxDownloadSize; size = [string]$_.Size; result = [string]$_.Result; ` +
		`categories = @($_.Categories | ForEach-Object { [string]$_.Name }) } })`
}

// pendingWindowsUpdates lists the updates that installWindowsUpdates would
// install. Windows Update reports a download size and update categories, but no
// unpacked size.
func pendingWindowsUpdates(ctx context.Context, logger logging.Logger, securityOnly bool) ([]pendingUpdate, error) {
	// Without -Install, Get-WindowsUpdate only searches, so this reports what the
	// install below is about to do.
	cmd := "Import-Module PSWindowsUpdate; $pending = @(Get-WindowsUpdate"
	if securityOnly {
		cmd += securityCategory
	}
	cmd += "); " + windowsUpdatesJSON("$pending")

	output, err := runPowerShell(ctx, logger, cmd)
	if err != nil {
		return nil, errw.Wrap(err, "listing pending Windows updates")
	}
	return parseWindowsUpdates(output)
}

// parseWindowsUpdates converts the JSON printed by [windowsUpdatesJSON] into
// updates.
func parseWindowsUpdates(output string) ([]pendingUpdate, error) {
	output = strings.TrimSpace(output)
	if output == "" {
		// Not every PowerShell version renders an empty array as "[]".
		return nil, nil
	}

	var infos []windowsUpdateInfo
	if err := json.Unmarshal([]byte(output), &infos); err != nil {
		return nil, errw.Wrapf(err, "parsing Windows updates: %s", output)
	}

	updates := make([]pendingUpdate, 0, len(infos))
	for _, info := range infos {
		updates = append(updates, pendingUpdate{
			Name:         windowsUpdateName(info),
			DownloadSize: windowsDownloadSize(info),
			// Categories are per-update rather than a single classification, so keep all
			// of them, separated by "/" to stay distinguishable inside a log line.
			Category: strings.Join(info.Categories, "/"),
			Result:   info.Result,
		})
	}
	return updates, nil
}

// windowsUpdateName labels an update by title, prefixed with its KB number when
// the title doesn't already carry it.
func windowsUpdateName(info windowsUpdateInfo) string {
	if info.KB != "" && !strings.Contains(info.Title, info.KB) {
		return info.KB + " " + info.Title
	}
	return info.Title
}

func windowsDownloadSize(info windowsUpdateInfo) uint64 {
	if info.DownloadSize > 0 {
		return info.DownloadSize
	}
	return parseSize(info.Size)
}

// installWindowsUpdates installs updates via the PSWindowsUpdate PowerShell module,
// returning one entry per update it processed, with Result reporting the stage the
// update reached, so the caller can log what actually landed rather than what was
// merely pending beforehand. An update that failed to install is a "Failed" entry
// in that list, not an error: PSWindowsUpdate reports per-update failures in its
// output rather than its exit code.
// Devices already configured to use a WSUS server (via Group Policy or registry) will
// automatically receive updates from that server without any extra configuration.
func installWindowsUpdates(ctx context.Context, logger logging.Logger, securityOnly bool) ([]pendingUpdate, error) {
	// -IgnoreReboot prevents PSWindowsUpdate from rebooting immediately; the agent
	// coordinates the reboot via the maintenance window.
	cmd := "Import-Module PSWindowsUpdate; $installed = @(Get-WindowsUpdate -Install -AcceptAll -IgnoreReboot"
	if securityOnly {
		cmd += securityCategory
	}
	cmd += "); " + windowsUpdatesJSON("$installed")

	output, err := runPowerShell(ctx, logger, cmd)
	if err != nil {
		return nil, errw.Wrap(err, "installing Windows updates")
	}

	installed, err := parseWindowsUpdates(output)
	if err != nil {
		// The install itself succeeded, we just can't say from its output what it
		// covered. The caller falls back to the pending list.
		logger.Warnw("Could not determine which Windows updates were installed", "err", err)
		return nil, nil
	}
	return dedupeWindowsUpdates(installed), nil
}

// dedupeWindowsUpdates collapses the stage rows Get-WindowsUpdate -Install emits —
// one per update for each of "Accepted", "Downloaded" and "Installed" (or
// "Failed") — into a single entry per update carrying the last stage it reached.
// Updates keep the order they first appeared in, and the stage rows arrive in
// chronological order, so the last row seen for a name is its final stage.
func dedupeWindowsUpdates(updates []pendingUpdate) []pendingUpdate {
	indexByName := make(map[string]int, len(updates))
	deduped := make([]pendingUpdate, 0, len(updates))
	for _, update := range updates {
		if i, ok := indexByName[update.Name]; ok {
			deduped[i] = update
			continue
		}
		indexByName[update.Name] = len(deduped)
		deduped = append(deduped, update)
	}
	return deduped
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

// silenceProgress suppresses the progress stream for the rest of a script.
// Install-Module and Windows Update downloads both report progress, which renders
// into the output we capture and parse.
const silenceProgress = `$ProgressPreference = 'SilentlyContinue'; `

// runPowerShell executes a PowerShell command, returning its standard output only.
// Standard error is deliberately kept out of that: callers parse the output, and
// PSWindowsUpdate writes warnings (a pending reboot, for one) to stderr, which would
// otherwise land in the middle of the data. It is reported in the error instead.
func runPowerShell(ctx context.Context, logger logging.Logger, script string) (string, error) {
	script = silenceProgress + script
	cmd := exec.CommandContext(ctx, "powershell",
		"-NonInteractive", "-NoProfile", "-ExecutionPolicy", "RemoteSigned",
		"-Command", script,
	)
	logger.Debugw("Executing powershell command", "script", script)
	output, err := cmd.Output()
	if err != nil {
		var stderr []byte
		if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
			stderr = exitErr.Stderr
		}
		return string(output), fmt.Errorf("powershell: %w\nstdout: %s\nstderr: %s", err, output, stderr)
	}
	logger.Debugw("Powershell command succeeded", "script", script, "output", string(output))
	return string(output), nil
}
