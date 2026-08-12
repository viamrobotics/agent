package agent

import (
	"testing"
	"time"

	"go.viam.com/test"
)

func TestBootFields(t *testing.T) {
	bootTime := time.Date(2026, time.August, 12, 15, 4, 5, 0, time.UTC)

	t.Run("agent started with the system", func(t *testing.T) {
		fields := bootFields(bootTime, bootTime.Add(time.Second*30))
		test.That(t, fields, test.ShouldResemble, []any{
			"boot_time", "2026-08-12T15:04:05Z",
			"system_uptime", "30s",
			"system_uptime_us", int64(30_000_000),
			"followed_system_boot", true,
		})
	})

	t.Run("agent restarted long after boot", func(t *testing.T) {
		fields := bootFields(bootTime, bootTime.Add(time.Hour*3))
		test.That(t, fields, test.ShouldResemble, []any{
			"boot_time", "2026-08-12T15:04:05Z",
			"system_uptime", "3h0m0s",
			"system_uptime_us", int64(3 * 60 * 60 * 1_000_000),
			"followed_system_boot", false,
		})
	})
}
