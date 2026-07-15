package syscfg

import (
	"errors"
	"slices"
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

// isManaged returns true for the set of configuration values for
// `os_auto_upgrade_type` that are considered "managed upgrades", i.e.
// viam-agent manages performing the upgrades and related tasks like triggering
// reboots rather than configuring a system daemon to do so.
func isManaged(mode string) bool {
	return slices.Contains([]string{utils.OSAutoUpgradeManagedAll, utils.OSAutoUpgradeManagedSecurity}, mode)
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
