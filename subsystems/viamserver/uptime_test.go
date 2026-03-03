package viamserver

import (
	"testing"
	"time"

	"go.viam.com/test"
)

func TestUptime(t *testing.T) {
	t.Run("returns nil when startTime is zero (server not running)", func(t *testing.T) {
		s := &Subsystem{}
		test.That(t, s.startTime.IsZero(), test.ShouldBeTrue)
		test.That(t, s.Uptime(), test.ShouldBeNil)
	})

	t.Run("returns positive duration when startTime is set", func(t *testing.T) {
		s := &Subsystem{}
		s.startTime = time.Now().Add(-5 * time.Second)

		uptime := s.Uptime()
		test.That(t, uptime, test.ShouldNotBeNil)
		test.That(t, uptime.AsDuration(), test.ShouldBeGreaterThan, 0)
	})

	t.Run("Uptime is thread-safe via mu", func(t *testing.T) {
		s := &Subsystem{}

		// Set startTime under the lock (as Start() would do).
		s.mu.Lock()
		s.startTime = time.Now()
		s.mu.Unlock()

		uptime := s.Uptime()
		test.That(t, uptime, test.ShouldNotBeNil)

		// Clear startTime under the lock (as the exit goroutine would do).
		s.mu.Lock()
		s.startTime = time.Time{}
		s.mu.Unlock()

		test.That(t, s.Uptime(), test.ShouldBeNil)
	})
}
