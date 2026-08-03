package syscfg

import (
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
)

const (
	defaultUpgradeInterval = 24 * time.Hour
	minimumUpgradeInterval = time.Hour
	// maintenanceRetryInterval is how often to retry an upgrade that was blocked
	// by viam-server's maintenance window, instead of waiting for the full
	// configured interval.
	maintenanceRetryInterval = 5 * time.Minute
)

// errBlockedByMaintenanceWindow is returned by runManagedUpgrade when the
// upgrade could not run because viam-server's maintenance window is closed.
var errBlockedByMaintenanceWindow = errors.New("upgrade blocked by maintenance window")

// upgradeState tracks whether a managed OS upgrade is executing, so the reboot
// check can refuse to interrupt one. The OS "reboot required" indicators we poll
// are set by individual packages as they install, not at the end of the batch,
// so they appear while a transaction is still in flight.
//
// Carries its own mutex rather than reusing the subsystem lock: Stop holds that
// lock while waiting for the upgrade worker to exit, so any lock the worker takes
// mid-upgrade is a deadlock risk.
type upgradeState struct {
	mu         sync.Mutex
	inProgress bool
}

// begin marks an upgrade as running and returns the function clearing the mark,
// which callers should defer.
func (u *upgradeState) begin() func() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.inProgress = true
	return func() {
		u.mu.Lock()
		defer u.mu.Unlock()
		u.inProgress = false
	}
}

// running reports whether an upgrade is executing right now.
func (u *upgradeState) running() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.inProgress
}

// blockNotice logs the first time a pending reboot is held back, then stays
// quiet until the condition clears, so a once-a-minute poll does not fill the
// log. Without it, a held-back reboot would be silent and hard to diagnose.
type blockNotice struct {
	mu     sync.Mutex
	logged bool
}

// note logs msg if blocked is newly true, and rearms once blocked goes false.
func (b *blockNotice) note(logger logging.Logger, blocked bool, msg string) {
	b.mu.Lock()
	shouldLog := blocked && !b.logged
	b.logged = blocked
	b.mu.Unlock()

	if shouldLog {
		logger.Info(msg)
	}
}

// nextUpgradeInterval returns how long to wait before the next managed upgrade
// attempt, given the error (if any) from the previous attempt. When the previous
// attempt was blocked by the maintenance window we retry sooner so the upgrade
// runs promptly once the window opens.
func nextUpgradeInterval(err error, interval time.Duration) time.Duration {
	if errors.Is(err, errBlockedByMaintenanceWindow) {
		return maintenanceRetryInterval
	}
	return interval
}

// logIfNewlyBlocked emits a warning the first time an upgrade attempt is blocked
// by the maintenance window, using alreadyLogged to avoid repeating the warning
// on every retry. It resets once upgrades are no longer blocked.
func logIfNewlyBlocked(logger logging.Logger, err error, alreadyLogged *bool) {
	blocked := errors.Is(err, errBlockedByMaintenanceWindow)
	if blocked && !*alreadyLogged {
		logger.Warn("managed upgrade check blocked by maintenance window, will retry until window opens")
	}
	*alreadyLogged = blocked
}

// isManaged returns true for the set of configuration values for
// `os_auto_upgrade_type` that are considered "managed upgrades", i.e.
// viam-agent manages performing the upgrades and related tasks like triggering
// reboots rather than configuring a system daemon to do so.
func isManaged(mode string) bool {
	return slices.Contains([]string{utils.OSAutoUpgradeManagedAll, utils.OSAutoUpgradeManagedSecurity}, mode)
}

// logManagedUpgradesStarted announces that agent-managed OS upgrades are active.
// Without this the only positive signal is an upgrade actually running, which
// never happens on a device whose maintenance window has been closed since boot.
func logManagedUpgradesStarted(logger logging.Logger, mode string, interval time.Duration) {
	logger.Infow("Managed OS upgrades enabled, viam-agent will install updates directly",
		"os_auto_upgrade_type", mode,
		"check_interval", interval,
	)
}

func clampUpgradeInterval(logger logging.Logger, hours float64) time.Duration {
	if hours == 0 {
		return defaultUpgradeInterval
	}
	interval := time.Duration(float64(time.Hour) * hours)
	if interval < minimumUpgradeInterval {
		logger.Warnw("Configured upgrade check interval too low, using minimum",
			"configured_interval", interval,
			"minimum_interval", minimumUpgradeInterval,
		)
		return minimumUpgradeInterval
	}
	return interval
}
