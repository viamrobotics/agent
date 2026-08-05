package syscfg

// This file probes for package manager transactions the agent did not start — a
// concurrent unattended-upgrades run, or an operator at a shell. The in-process
// upgradeState flag covers neither, and does not survive an agent restart; these
// locks live in the kernel and do.

import (
	"io"
	"os"

	"go.viam.com/rdk/logging"
	goutils "go.viam.com/utils"
	"golang.org/x/sys/unix"
)

// osUpgradeInProgress reports whether another process holds any of paths as a
// transaction lock. Missing and unreadable files both read as not-held, so that a
// permanently failing check cannot block reboots forever.
func osUpgradeInProgress(logger logging.Logger, paths []string) bool {
	for _, path := range paths {
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
// F_GETLK asks the kernel whether a lock would conflict without acquiring
// anything, so it cannot interfere with the transaction it inspects. It reports
// only *other* processes' locks, which suits us: the package manager we run is
// always a child process, already covered by upgradeState.
func packageLockHeld(path string) (bool, int32, error) {
	// Not O_CREATE: we must never create a lock file a package manager would later
	// rely on. Paths are compiled in, never from config.
	//nolint: gosec
	f, err := os.Open(path)
	if err != nil {
		return false, 0, err
	}
	defer func() {
		goutils.UncheckedError(f.Close())
	}()

	// Len 0 means "to end of file".
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
func (s *Subsystem) rebootBlockedByOSUpgrade(pkgMgr packageManager) bool {
	blocked := osUpgradeInProgress(s.logger, pkgMgr.lockPaths())
	s.rebootBlocked.note(s.logger, blocked,
		"OS reboot pending, but a package manager transaction is in progress; waiting for it to finish")
	return blocked
}
