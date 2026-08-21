package agent

import (
	"time"

	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
)

// SystemBootFields returns activity event fields describing the current OS boot, so a
// restart of the agent alone can be told apart from a reboot of the whole device.
// Returns nil if the boot time cannot be determined.
func SystemBootFields(logger logging.Logger) []any {
	bootTime, err := utils.SystemBootTime()
	if err != nil {
		logger.Warnw("cannot determine system boot time", "err", err)
		return nil
	}
	return bootFields(bootTime, time.Now())
}

func bootFields(bootTime, now time.Time) []any {
	uptime := now.Sub(bootTime)
	return []any{
		"boot_time", bootTime.UTC().Format(time.RFC3339),
		"system_uptime", uptime.String(),
		"system_uptime_us", uptime.Microseconds(),
	}
}
