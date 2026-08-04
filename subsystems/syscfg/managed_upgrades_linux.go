package syscfg

// This file implements agent-managed OS package upgrades.
// Unlike the unattended-upgrades approach (which delegates to a systemd timer),
// managed mode has the agent run apt upgrades directly on a controlled schedule
// and coordinate reboots with viam-server's maintenance window.
//
// Supported package managers (tried in preference order):
//   - dnf  - Fedora, RHEL 8+, Rocky Linux, AlmaLinux, etc.
//   - apt-get - Debian, Ubuntu, Raspberry Pi OS, etc.
//   - yum  - RHEL 7, CentOS 7

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/samber/lo"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
)

// categorySecurity is the [pendingUpdate] Category for a security update, and the
// only category Linux package managers let us identify per package. Windows
// reports its own category names instead.
const categorySecurity = "security"

// startManagedUpgrades launches the background goroutine that periodically runs upgrades.
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

// NeedsOSReboot reports whether a reboot is pending from installed package
// updates and can be taken now. A transaction in flight defers it, not cancels
// it: the answer flips back to true once that finishes.
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

	// We only take over reboots in managed upgrade mode. An already-latched reboot
	// is honoured regardless, so leaving managed mode cannot strand one.
	if !needReboot && !isManaged(autoUpgradeType) {
		return false
	}

	// Needed by both checks below: which reboot indicator to read, and which lock
	// files a transaction would hold.
	pkgMgr, err := getPackageManager(s.logger)
	if err != nil {
		s.logger.Warnw("Could not detect package manager to check for OS reboot", "err", err)
		// A reboot already known to be pending still stands: with no package manager
		// found there is no transaction to interrupt, matching the fail-open lock check.
		return needReboot
	}

	// Skipped when already cached: a pending reboot cannot become unnecessary until
	// the reboot happens, and some checks (RHEL's needs-restarting) are slow.
	if !needReboot {
		if !pkgMgr.needsReboot(ctx) {
			return false
		}

		s.mu.Lock()
		s.needsOSReboot = true
		s.mu.Unlock()
	}

	// A reboot is pending; whether it is safe to act on is a separate question. Hold
	// off while any package transaction runs, including one we did not start.
	return !s.rebootBlockedByOSUpgrade(pkgMgr)
}

// getPackageManager returns an implementation of [packageManager] that
// matches the package manager binaries available on the OS. A variable so tests
// can substitute a fake.
var getPackageManager = func(logger logging.Logger) (packageManager, error) {
	type pmOption struct {
		binary      string
		constructor func() packageManager
	}
	pms := []pmOption{
		{
			"apt-get",
			func() packageManager { return aptPackageManager{logger: logger.Sublogger("apt")} },
		},
		{
			"dnf",
			func() packageManager { return rpmPackageManager{logger: logger.Sublogger("dnf"), useDnf: true} },
		},
		{
			"yum",
			func() packageManager { return rpmPackageManager{logger: logger.Sublogger("yum"), useDnf: false} },
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

	pm, err := getPackageManager(s.logger)
	if err != nil {
		s.logger.Warnw("skipping managed OS upgrade", "error", err)
		return err
	}

	securityOnly := mode == utils.OSAutoUpgradeManagedSecurity
	s.logger.Infow("Running managed OS package update",
		"package_manager", pm,
		"os_auto_upgrade_type", mode,
		"security_only", securityOnly,
	)

	// Block reboots for the duration of the upgrade cycle: postinst scripts create
	// /var/run/reboot-required, so the reboot check would otherwise see it while
	// dpkg is still working through the rest of the batch. prepare is covered too,
	// since it may install helper packages of its own.
	upgradeDone := s.upgrade.begin()
	defer upgradeDone()

	if err := pm.prepare(ctx, securityOnly); err != nil {
		s.logger.Errorw("Failed to refresh OS package metadata, skipping upgrade",
			"package_manager", pm, "err", err)
		return err
	}

	pending, listErr := pm.pendingUpgrades(ctx, securityOnly)
	updates := updateSummary{updates: pending, listErr: listErr}
	logPendingUpdates(s.logger, updates, "package_manager", pm, "security_only", securityOnly)

	upgradeErr := pm.runUpgrade(ctx, securityOnly)
	logUpgradeResult(ctx, s.logger, updates, upgradeErr, "package_manager", pm, "security_only", securityOnly)
	if upgradeErr != nil {
		return upgradeErr
	}

	// Check if a reboot is required.
	if pm.needsReboot(ctx) {
		s.mu.Lock()
		s.needsOSReboot = true
		s.mu.Unlock()
		s.logger.Info("OS reboot required after package updates, will reboot when maintenance window opens")
	}

	return nil
}

// pkgCmd runs a package manager command, setting DEBIAN_FRONTEND=noninteractive
// to suppress interactive prompts on apt-based systems (ignored elsewhere).
func pkgCmd(ctx context.Context, logger logging.Logger, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	logger.Debugw("Executing package management command", "cmd", cmd.String())
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w\n%s", name, args, err, output)
	}
	logger.Debugw("Package management command succeeded", "cmd", cmd.String(), "output", string(output))
	return nil
}

type packageManager interface {
	fmt.Stringer
	// prepare refreshes cached package metadata and installs or writes anything
	// else needed to list and install upgrades. It must run before
	// pendingUpgrades or runUpgrade, otherwise both work from stale metadata.
	prepare(ctx context.Context, securityOnly bool) error
	// pendingUpgrades lists the upgrades that runUpgrade would install, for
	// logging, filling in as much detail as the package manager reports. Callers
	// still run the upgrade if this fails.
	pendingUpgrades(ctx context.Context, securityOnly bool) ([]pendingUpdate, error)
	runUpgrade(ctx context.Context, securityOnly bool) error
	needsReboot(ctx context.Context) bool
	// lockPaths are the files this package manager fcntl-locks for the duration of a
	// transaction, used to spot installs the agent did not start.
	lockPaths() []string
}
