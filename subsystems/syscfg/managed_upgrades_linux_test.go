package syscfg

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
	"go.viam.com/test"
)

// A reboot must never be reported while an upgrade is installing, even once a
// reboot is already known to be pending, because rebooting mid-transaction can
// leave the package database broken.
func TestNeedsOSRebootWaitsForUpgradeToFinish(t *testing.T) {
	withNoPackageLocks(t)

	newSubsystem := func() *Subsystem {
		return &Subsystem{
			logger: logging.NewTestLogger(t),
			cfg: utils.SystemConfiguration{
				OSAutoUpgradeType: utils.OSAutoUpgradeManagedSecurity,
			},
		}
	}

	t.Run("pending reboot is reported when idle", func(t *testing.T) {
		s := newSubsystem()
		s.needsOSReboot = true
		test.That(t, s.NeedsOSReboot(context.Background()), test.ShouldBeTrue)
	})

	t.Run("pending reboot is suppressed while upgrading", func(t *testing.T) {
		s := newSubsystem()
		s.needsOSReboot = true
		defer s.upgrade.begin()()
		test.That(t, s.NeedsOSReboot(context.Background()), test.ShouldBeFalse)
	})

	t.Run("reboot is reported again once the upgrade finishes", func(t *testing.T) {
		s := newSubsystem()
		s.needsOSReboot = true
		done := s.upgrade.begin()
		test.That(t, s.NeedsOSReboot(context.Background()), test.ShouldBeFalse)
		done()
		test.That(t, s.NeedsOSReboot(context.Background()), test.ShouldBeTrue)
	})

	// The in-process flag above only covers upgrades this agent runs. A package
	// transaction started by anything else must hold the reboot back too.
	t.Run("pending reboot is suppressed by an external package transaction", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "lock")
		f, err := os.Create(path)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, f.Close(), test.ShouldBeNil)

		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestHelperHoldsPackageLock$")
		cmd.Env = append(os.Environ(), lockHelperPathEnv+"="+path)
		stdin, err := cmd.StdinPipe()
		test.That(t, err, test.ShouldBeNil)
		stdout, err := cmd.StdoutPipe()
		test.That(t, err, test.ShouldBeNil)
		test.That(t, cmd.Start(), test.ShouldBeNil)
		defer func() {
			stdin.Close()
			cmd.Wait()
		}()

		var locked bool
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			if scanner.Text() == "locked" {
				locked = true
				break
			}
		}
		test.That(t, locked, test.ShouldBeTrue)

		packageLockPaths = []string{path}
		defer func() { packageLockPaths = nil }()

		s := newSubsystem()
		s.needsOSReboot = true
		test.That(t, s.NeedsOSReboot(context.Background()), test.ShouldBeFalse)

		// Releasing the lock unblocks the reboot.
		stdin.Close()
		test.That(t, cmd.Wait(), test.ShouldBeNil)
		test.That(t, s.NeedsOSReboot(context.Background()), test.ShouldBeTrue)
	})
}
