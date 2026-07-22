package main

import (
	"os"
	"testing"

	"go.viam.com/test"
)

func TestPidIsSelfOrThread(t *testing.T) {
	stale, _ := pidIsSelfOrThread(os.Getpid())
	test.That(t, stale, test.ShouldBeTrue)

	// PID 1 (init/systemd/launchd) is a real, foreign process on all platforms.
	stale, _ = pidIsSelfOrThread(1)
	test.That(t, stale, test.ShouldBeFalse)
}
