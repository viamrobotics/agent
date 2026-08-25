package syscfg

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
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

	updateActivityStart    = "os_update_start"
	updateActivityComplete = "os_update_complete"
	updateActivityFail     = "os_update_fail"
	updateActivityAbort    = "os_update_abort"
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

// pendingUpdate describes a single update that a managed upgrade is about to
// install, as reported by the platform's package manager.
//
// Package managers differ in what they report, so only Name is guaranteed to be
// populated. The remaining fields carry whatever the underlying tool exposes:
// sizes are zero and Category is empty when it isn't available. See each
// packageManager's pendingUpgrades implementation for what a given platform fills
// in.
//
// The whole struct is logged as-is, so the json tags decide what the fields are
// called in the logs. Everything the package manager didn't report is omitted
// rather than logged as an empty string or a zero size.
type pendingUpdate struct {
	// Name identifies the package, including its architecture when the package
	// manager reports one.
	Name string `json:"name"`
	// Version is the version being installed.
	Version string `json:"version,omitempty"`
	// CurrentVersion is the installed version being replaced, and is empty for
	// packages being installed for the first time.
	CurrentVersion string `json:"current_version,omitempty"`
	// DownloadSize is the compressed size fetched from the repository, in bytes.
	DownloadSize uint64 `json:"download_size,omitempty"`
	// InstalledSize is the size the package occupies on disk once unpacked, in
	// bytes.
	InstalledSize uint64 `json:"installed_size,omitempty"`
	// Category classifies the update, e.g. "security". Package managers that don't
	// classify individual packages leave this empty.
	Category string `json:"category,omitempty"`
	// Result is how far installing this update got, e.g. "Installed" or "Failed".
	// Only Windows Update reports per-update outcomes; Linux package managers and
	// pending-update lists leave it empty.
	Result string `json:"result,omitempty"`
}

// updateSummary describes the updates a managed upgrade is about to install.
// Listing updates is best effort: when it fails we still attempt the upgrade, and
// listErr is logged in place of the update list so the logs say why the list is
// missing rather than implying nothing was pending.
type updateSummary struct {
	updates []pendingUpdate
	listErr error
}

// shouldContinue returns true if there may be more work to do to install os
// updates, false otherwise.
func (us updateSummary) shouldContinue() bool {
	return len(us.updates) > 0 || us.listErr != nil
}

// sizeSuffixes maps the unit suffixes package managers print sizes with to their
// multiplier. Both the SI-style ("2.3 M") and binary ("2.3 MiB") spellings appear
// in practice, and both mean a power of 1024 in this context.
var sizeSuffixes = []struct {
	suffix     string
	multiplier uint64
}{
	{"k", 1 << 10},
	{"m", 1 << 20},
	{"g", 1 << 30},
	{"t", 1 << 40},
}

// parseSize reads a size that a package manager may report either as a plain byte
// count ("2799652") or as a human readable string ("2.7 M", "2.7 MiB", "2.7MB").
// It returns 0 for anything it can't make sense of, matching the "size unknown"
// zero value of [pendingUpdate].
func parseSize(size string) uint64 {
	size = strings.ToLower(strings.TrimSpace(size))
	size = strings.TrimSuffix(strings.TrimSuffix(size, "b"), "i")
	multiplier := uint64(1)
	for _, unit := range sizeSuffixes {
		if strings.HasSuffix(size, unit.suffix) {
			size = strings.TrimSuffix(size, unit.suffix)
			multiplier = unit.multiplier
			break
		}
	}
	value, err := strconv.ParseFloat(strings.TrimSpace(size), 64)
	if err != nil || value < 0 {
		return 0
	}
	return uint64(value * float64(multiplier))
}

// logPendingUpdates summarizes the updates about to be installed. Call this
// immediately before applying them, so a device that hangs or reboots mid-upgrade
// still leaves behind a record of what it was installing.
func logPendingUpdates(logger logging.Logger, updates updateSummary, keysAndValues ...any) {
	if updates.listErr != nil {
		logger.Activity("system", updateActivityStart, append([]any{"update_list_err", updates.listErr}, keysAndValues...)...)
		return
	}
	if len(updates.updates) == 0 {
		logger.Infow("No OS updates pending, nothing to install", keysAndValues...)
		return
	}
	logger.Activity("system", updateActivityStart, append([]any{"updates", updates.updates}, keysAndValues...)...)
}

// logUpgradeResult reports how the upgrade went, with installed carrying the
// packages the package manager's output reported actually installing. When the
// package manager didn't say, the list is omitted entirely rather than logged
// empty or guessed at: logPendingUpdates already recorded what the upgrade set
// out to install. A cancelled ctx means the agent is shutting down and killed
// the upgrade itself, which isn't an error worth alarming about.
func logUpgradeResult(ctx context.Context, logger logging.Logger, installed []pendingUpdate, err error, keysAndValues ...any) {
	var fields []any
	if len(installed) > 0 {
		fields = append(fields, "updates", installed)
	}
	fields = append(fields, keysAndValues...)
	switch {
	case err != nil && ctx.Err() != nil:
		logger.Activity("system", updateActivityAbort, append(fields, "err", err)...)
	case err != nil:
		logger.Activity("system", updateActivityFail, append(fields, "err", err)...)
	default:
		logger.Activity("system", updateActivityComplete, fields...)
	}
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
