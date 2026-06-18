package syscfg

import (
	"slices"
	"time"

	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
)

const (
	defaultUpgradeInterval = 24 * time.Hour
	minimumUpgradeInterval = time.Hour
)

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
