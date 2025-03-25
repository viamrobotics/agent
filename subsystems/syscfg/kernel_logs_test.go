package syscfg

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
	"go.viam.com/test"
)

// createMockJournalctl creates a temporary mock journalctl command and modifies PATH to find it.
func createMockJournalctl(t *testing.T) func() {
	// Create a temporary directory for the mock command
	tmpDir := t.TempDir()
	mockPath := filepath.Join(tmpDir, "journalctl")

	// Create the mock command that outputs test log entries and reads from stdin for new entries
	//nolint:lll
	mockContent := `#!/bin/bash
# Initial entries
echo '{"PRIORITY":"3","SYSLOG_IDENTIFIER":"kernel","_HOSTNAME":"raspberrypi","_BOOT_ID":"test-boot-id","__REALTIME_TIMESTAMP":"1709234567890123","__MONOTONIC_TIMESTAMP":"1234567890","MESSAGE":"Test kernel error"}'
echo '{"PRIORITY":"4","SYSLOG_IDENTIFIER":"kernel","_HOSTNAME":"raspberrypi","_BOOT_ID":"test-boot-id","__REALTIME_TIMESTAMP":"1709234567890124","__MONOTONIC_TIMESTAMP":"1234567891","MESSAGE":"Test kernel warning"}'
echo '{"PRIORITY":"6","SYSLOG_IDENTIFIER":"kernel","_HOSTNAME":"raspberrypi","_BOOT_ID":"test-boot-id","__REALTIME_TIMESTAMP":"1709234567890125","__MONOTONIC_TIMESTAMP":"1234567892","MESSAGE":"Test kernel info"}'

# Sleep to simulate time passing
sleep 2

# Output new entries after delay
echo '{"PRIORITY":"3","SYSLOG_IDENTIFIER":"kernel","_HOSTNAME":"raspberrypi","_BOOT_ID":"test-boot-id","__REALTIME_TIMESTAMP":"1709234567890126","__MONOTONIC_TIMESTAMP":"1234567893","MESSAGE":"New kernel entry after forwarder started"}'
`
	if err := os.WriteFile(mockPath, []byte(mockContent), 0o755); err != nil {
		t.Fatalf("Failed to create mock journalctl: %v", err)
	}

	// Save original PATH
	oldPath := os.Getenv("PATH")

	// Modify PATH to find our mock command
	t.Setenv("PATH", tmpDir+":"+oldPath)

	// Return cleanup function
	return func() {
		t.Setenv("PATH", oldPath)
	}
}

func TestKernelLogForwarder(t *testing.T) {
	cleanup := createMockJournalctl(t)
	defer cleanup()

	logger, logs := logging.NewObservedTestLogger(t)

	cfg := utils.SystemConfiguration{
		ForwardKernelLogs: true,
	}

	k := NewKernelLogForwarder(context.Background(), logger, cfg)

	// On start, we should see kernel forwarder start log
	err := k.Start()
	test.That(t, err, test.ShouldBeNil)

	// Wait for initial logs
	time.Sleep(100 * time.Millisecond)

	// Verify initial logs
	initialLogs := logs.All()
	test.That(t, len(initialLogs), test.ShouldEqual, 4) // 3 kernel logs + start message

	// Wait for new logs
	time.Sleep(3 * time.Second)

	// Stop forwarding to ensure all logs are flushed
	err = k.Stop()
	test.That(t, err, test.ShouldBeNil)

	// Get all logs and verify
	allLogs := logs.All()
	test.That(t, len(allLogs), test.ShouldEqual, 6) // 4 kernel logs + start + stop messages

	// Verify the logs in order
	//nolint:lll
	expectedLogs := []string{
		"Started Kernel logs forwarding",
		"[syslog_id=kernel boot_id=test-boot-id realtime=2024-02-29T19:22:47.890123Z monotonic=1.23456789s since boot] Test kernel error",
		"[syslog_id=kernel boot_id=test-boot-id realtime=2024-02-29T19:22:47.890124Z monotonic=1.234567891s since boot] Test kernel warning",
		"[syslog_id=kernel boot_id=test-boot-id realtime=2024-02-29T19:22:47.890125Z monotonic=1.234567892s since boot] Test kernel info",
		"[syslog_id=kernel boot_id=test-boot-id realtime=2024-02-29T19:22:47.890126Z monotonic=1.234567893s since boot] New kernel entry after forwarder started",
		"Stopped Kernel logs forwarding",
	}

	for i, log := range allLogs {
		test.That(t, log.Message, test.ShouldEqual, expectedLogs[i])
	}
}

func TestKernelLogForwarderDisabled(t *testing.T) {
	cleanup := createMockJournalctl(t)
	defer cleanup()

	logger, logs := logging.NewObservedTestLogger(t)
	cfg := utils.SystemConfiguration{
		ForwardKernelLogs: false,
	}
	k := NewKernelLogForwarder(context.Background(), logger, cfg)
	err := k.Start()
	test.That(t, err, test.ShouldBeNil)

	// Wait a bit to ensure no logs are forwarded
	time.Sleep(100 * time.Millisecond)

	// Stop forwarding to ensure all logs are flushed
	err = k.Stop()
	test.That(t, err, test.ShouldBeNil)

	// Verify no logs were forwarded
	allLogs := logs.All()
	test.That(t, len(allLogs), test.ShouldEqual, 0)
}

func TestKernelLogForwarderUpdate(t *testing.T) {
	cleanup := createMockJournalctl(t)
	defer cleanup()

	logger, logs := logging.NewObservedTestLogger(t)

	cfg := utils.SystemConfiguration{
		ForwardKernelLogs: false,
	}

	k := NewKernelLogForwarder(context.Background(), logger, cfg)

	// Start with forwarding disabled
	err := k.Start()
	test.That(t, err, test.ShouldBeNil)

	// Update to enable forwarding
	cfg.ForwardKernelLogs = true
	err = k.Update(cfg)
	test.That(t, err, test.ShouldBeNil)

	err = k.Start()
	test.That(t, err, test.ShouldBeNil)

	time.Sleep(100 * time.Millisecond)

	// Stop forwarding to ensure all logs are flushed
	err = k.Stop()
	test.That(t, err, test.ShouldBeNil)

	// Verify logs are forwarded
	allLogs := logs.All()
	test.That(t, len(allLogs), test.ShouldBeGreaterThan, 0)
}

func TestKernelLogForwarderErrorHandling(t *testing.T) {
	cleanup := createMockJournalctl(t)
	defer cleanup()

	logger := logging.NewTestLogger(t)

	cfg := utils.SystemConfiguration{
		ForwardKernelLogs: true,
	}

	k := NewKernelLogForwarder(context.Background(), logger, cfg)

	t.Run("command error", func(t *testing.T) {
		// Temporarily modify PATH to make journalctl unavailable
		oldPath := os.Getenv("PATH")
		t.Setenv("PATH", "")
		defer t.Setenv("PATH", oldPath)

		err := k.Start()
		test.That(t, err, test.ShouldBeNil)
	})

	t.Run("stop after context cancellation", func(t *testing.T) {
		err := k.Start()
		test.That(t, err, test.ShouldBeNil)

		// Cancel context
		k.cancel()

		err = k.Stop()
		test.That(t, err, test.ShouldBeNil)
	})
}

func TestKernelLogForwarderCleanup(t *testing.T) {
	cleanup := createMockJournalctl(t)
	defer cleanup()

	logger, logs := logging.NewObservedTestLogger(t)
	cfg := utils.SystemConfiguration{
		ForwardKernelLogs: true,
	}
	k := NewKernelLogForwarder(context.Background(), logger, cfg)

	// Start the forwarder
	err := k.Start()
	test.That(t, err, test.ShouldBeNil)

	// Wait for start message
	time.Sleep(100 * time.Millisecond)

	// Verify forwarder is running
	test.That(t, k.cmd, test.ShouldNotBeNil)

	// Test cleanup during Stop
	err = k.Stop()
	test.That(t, err, test.ShouldBeNil)
	test.That(t, k.cmd, test.ShouldBeNil)
	test.That(t, logs.All()[len(logs.All())-1].Message, test.ShouldEqual, "Stopped Kernel logs forwarding")

	// Start again
	err = k.Start()
	test.That(t, err, test.ShouldBeNil)

	// Test cleanup during Start when disabled
	cfg.ForwardKernelLogs = false
	err = k.Update(cfg)
	test.That(t, err, test.ShouldBeNil)

	err = k.Start()
	test.That(t, err, test.ShouldBeNil)
	test.That(t, k.cmd, test.ShouldBeNil)
	test.That(t, logs.All()[len(logs.All())-1].Message, test.ShouldEqual, "Stopped Kernel logs forwarding")
}

func TestKernelLogForwarderToggle(t *testing.T) {
	cleanup := createMockJournalctl(t)
	defer cleanup()

	logger, logs := logging.NewObservedTestLogger(t)
	cfg := utils.SystemConfiguration{
		ForwardKernelLogs: true,
	}
	k := NewKernelLogForwarder(context.Background(), logger, cfg)

	// Start with forwarding enabled
	err := k.Start()
	test.That(t, err, test.ShouldBeNil)

	// Wait for initial logs
	time.Sleep(100 * time.Millisecond)

	// Verify we got initial logs
	initialLogs := logs.All()
	test.That(t, len(initialLogs), test.ShouldBeGreaterThan, 0)

	// Disable forwarding
	cfg.ForwardKernelLogs = false
	err = k.Update(cfg)
	test.That(t, err, test.ShouldBeNil)
	err = k.Start()
	test.That(t, err, test.ShouldBeNil)

	// Create new logger to check only new logs
	logger, logs = logging.NewObservedTestLogger(t)
	k.logger = logger

	// Wait a bit to ensure no logs are forwarded while disabled
	time.Sleep(100 * time.Millisecond)
	test.That(t, len(logs.All()), test.ShouldEqual, 0)

	// Re-enable forwarding
	cfg.ForwardKernelLogs = true
	err = k.Update(cfg)
	test.That(t, err, test.ShouldBeNil)
	err = k.Start()
	test.That(t, err, test.ShouldBeNil)

	// Wait for new logs
	time.Sleep(3 * time.Second)

	// Verify we got new logs after re-enabling
	newLogs := logs.All()
	test.That(t, len(newLogs), test.ShouldBeGreaterThan, 0)

	// Stop forwarding
	err = k.Stop()
	test.That(t, err, test.ShouldBeNil)
}
