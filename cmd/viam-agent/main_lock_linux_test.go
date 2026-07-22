package main

import (
	"os"
	"runtime"
	"syscall"
	"testing"

	"go.viam.com/test"
)

// A TID of one of this process's own OS threads must be recognized as stale: after an
// unclean shutdown, the previous boot's agent PID in the leftover lockfile frequently
// collides with a thread ID of the newly started agent (boot-time PID assignment is
// nearly deterministic), and threads pass the /proc/<pid>/exe binary check.
func TestPidIsSelfOrThreadWithOwnTID(t *testing.T) {
	// Pin this goroutine to an OS thread so the TID stays valid for the duration.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	tid := syscall.Gettid()
	if tid == os.Getpid() {
		t.Skip("goroutine is on the main thread; TID == PID exercises the self case instead")
	}

	stale, reason := pidIsSelfOrThread(tid)
	test.That(t, stale, test.ShouldBeTrue)
	test.That(t, reason, test.ShouldEqual, "an OS thread of this process")
}
