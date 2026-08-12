package agent

import (
	"time"

	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
)

// systemBootWindow is how soon after an OS boot an agent start is treated as part of
// that boot rather than as an agent-only restart. It covers the time the service
// manager takes to bring the agent up plus the agent's own initialization.
const systemBootWindow = 2 * time.Minute

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
		"followed_system_boot", uptime < systemBootWindow,
	}
}
