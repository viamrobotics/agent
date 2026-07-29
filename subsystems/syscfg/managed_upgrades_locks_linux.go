package syscfg

// This file probes whether a package manager transaction is running anywhere on
// the system, including one the agent did not start (a concurrent
// unattended-upgrades run, or an operator at a shell). The in-process
// upgradeState flag only covers upgrades this process is executing, and it does
// not survive an agent restart; these locks live in the kernel and do.

import (
	"context"
	"io"
	"os"

	"go.viam.com/rdk/logging"
	goutils "go.viam.com/utils"
	"golang.org/x/sys/unix"
)

// packageLockPaths are the lock files package managers hold for the duration of
// a transaction. A variable rather than a constant so tests can substitute
// paths they control.
var packageLockPaths = []string{
	// APT holds the frontend lock across an entire transaction, including the
	// dpkg invocations it spawns, so it is the broadest signal on Debian-likes.
	"/var/lib/dpkg/lock-frontend",
	// dpkg's own lock, held while unpacking and configuring packages.
	"/var/lib/dpkg/lock",
	// RPM's transaction lock, covering both dnf and yum.
	"/var/lib/rpm/.rpm.lock",
}

// osUpgradeInProgress reports whether any package manager currently holds a
// transaction lock. Missing lock files (RPM's on a Debian system, and vice
// versa) are not an error, they just mean that package manager is not present.
func osUpgradeInProgress(logger logging.Logger) bool {
	for _, path := range packageLockPaths {
		held, pid, err := packageLockHeld(path)
		switch {
		case err != nil:
			if !os.IsNotExist(err) {
				logger.Debugw("Could not check package manager lock", "path", path, "err", err)
			}
		case held:
			logger.Debugw("Package manager transaction in progress", "path", path, "pid", pid)
			return true
		}
	}
	return false
}

// packageLockHeld reports whether another process holds a write lock on path,
// along with the PID holding it.
//
// This uses F_GETLK rather than trying to take the lock: it asks the kernel
// whether a lock would conflict and returns the holder, without acquiring
// anything, so it cannot interfere with the transaction it is inspecting. Note
// that F_GETLK reports only locks held by *other* processes, which is what we
// want here, since the package manager we run is always a child process.
func packageLockHeld(path string) (bool, int32, error) {
	// Read-only, and deliberately not O_CREATE: we must never create a lock file
	// a package manager would later rely on. Paths come from packageLockPaths, not
	// from configuration or any other external input.
	//nolint: gosec
	f, err := os.Open(path)
	if err != nil {
		return false, 0, err
	}
	defer func() {
		goutils.UncheckedError(f.Close())
	}()

	// A zero Len means "to end of file", i.e. the whole file.
	flock := unix.Flock_t{
		Type:   unix.F_WRLCK,
		Whence: io.SeekStart,
		Start:  0,
		Len:    0,
	}
	if err := unix.FcntlFlock(f.Fd(), unix.F_GETLK, &flock); err != nil {
		return false, 0, err
	}
	if flock.Type == unix.F_UNLCK {
		return false, 0, nil
	}
	return true, flock.Pid, nil
}

// rebootBlockedByOSUpgrade reports whether a pending reboot must be held back
// because a package transaction is running, logging the first time it does.
func (s *Subsystem) rebootBlockedByOSUpgrade(_ context.Context) bool {
	blocked := osUpgradeInProgress(s.logger)
	s.rebootBlocked.note(s.logger, blocked,
		"OS reboot pending, but a package manager transaction is in progress; waiting for it to finish")
	return blocked
}
