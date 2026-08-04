package syscfg

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"go.viam.com/rdk/logging"
	"go.viam.com/test"
	"golang.org/x/sys/unix"
)

// lockHelperPathEnv names the lock file the helper process below should hold.
const lockHelperPathEnv = "SYSCFG_TEST_LOCK_HELPER_PATH"

// fakePackageManager stands in for apt/rpm so tests decide which lock files the
// probe examines.
type fakePackageManager struct {
	paths []string
}

func (f fakePackageManager) String() string                          { return "fake" }
func (f fakePackageManager) prepare(_ context.Context, _ bool) error { return nil }
func (f fakePackageManager) pendingUpgrades(_ context.Context, _ bool) ([]pendingUpdate, error) {
	return nil, nil
}
func (f fakePackageManager) runUpgrade(_ context.Context, _ bool) error { return nil }
func (f fakePackageManager) needsReboot(_ context.Context) bool         { return false }
func (f fakePackageManager) lockPaths() []string                        { return f.paths }

// withPackageLocks makes the detected package manager report exactly paths. With
// none, a real package transaction on the test machine cannot affect the result.
func withPackageLocks(t *testing.T, paths ...string) {
	t.Helper()
	original := getPackageManager
	getPackageManager = func(logging.Logger) (packageManager, error) {
		return fakePackageManager{paths: paths}, nil
	}
	t.Cleanup(func() { getPackageManager = original })
}

// TestHelperHoldsPackageLock is not a standalone test: it is the child process
// used by TestPackageLockHeld. F_GETLK ignores locks held by the calling process,
// so a separate process must hold the lock for the probe to observe anything.
func TestHelperHoldsPackageLock(t *testing.T) {
	path := os.Getenv(lockHelperPathEnv)
	if path == "" {
		t.Skip("helper process for TestPackageLockHeld")
	}

	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	test.That(t, err, test.ShouldBeNil)
	defer f.Close()

	flock := unix.Flock_t{Type: unix.F_WRLCK, Whence: io.SeekStart}
	test.That(t, unix.FcntlFlock(f.Fd(), unix.F_SETLK, &flock), test.ShouldBeNil)

	// Tell the parent the lock is held, then hold it until the parent closes stdin.
	_, err = os.Stdout.WriteString("locked\n")
	test.That(t, err, test.ShouldBeNil)
	io.Copy(io.Discard, os.Stdin)
}

func TestPackageLockHeld(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lock")
	f, err := os.Create(path)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, f.Close(), test.ShouldBeNil)

	t.Run("unlocked file", func(t *testing.T) {
		held, _, err := packageLockHeld(path)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, held, test.ShouldBeFalse)
	})

	t.Run("missing file is not an error state", func(t *testing.T) {
		_, _, err := packageLockHeld(filepath.Join(dir, "does-not-exist"))
		test.That(t, os.IsNotExist(err), test.ShouldBeTrue)
	})

	t.Run("locked by another process", func(t *testing.T) {
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

		held, pid, err := packageLockHeld(path)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, held, test.ShouldBeTrue)
		test.That(t, int(pid), test.ShouldEqual, cmd.Process.Pid)

		// The probe must not have taken the lock itself.
		held, _, err = packageLockHeld(path)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, held, test.ShouldBeTrue)

		t.Run("osUpgradeInProgress sees it", func(t *testing.T) {
			test.That(t, osUpgradeInProgress(logging.NewTestLogger(t), []string{path}), test.ShouldBeTrue)
		})
	})

	t.Run("osUpgradeInProgress tolerates absent lock files", func(t *testing.T) {
		missing := []string{filepath.Join(dir, "does-not-exist")}
		test.That(t, osUpgradeInProgress(logging.NewTestLogger(t), missing), test.ShouldBeFalse)
	})
}
