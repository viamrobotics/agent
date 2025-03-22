package syscfg

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
	"go.viam.com/test"
)

// createMockJournalctl creates a temporary mock journalctl command and modifies PATH to find it
func createMockJournalctl(t *testing.T) func() {
	// Create a temporary directory for the mock command
	tmpDir := t.TempDir()
	mockPath := filepath.Join(tmpDir, "journalctl")

	// Create the mock command that outputs test log entries
	mockContent := `#!/bin/bash
echo '{"PRIORITY":"3","SYSLOG_IDENTIFIER":"kernel","_HOSTNAME":"raspberrypi","_BOOT_ID":"test-boot-id","__REALTIME_TIMESTAMP":"1709234567890123","__MONOTONIC_TIMESTAMP":"1234567890","MESSAGE":"Test kernel error"}'
echo '{"PRIORITY":"4","SYSLOG_IDENTIFIER":"kernel","_HOSTNAME":"raspberrypi","_BOOT_ID":"test-boot-id","__REALTIME_TIMESTAMP":"1709234567890124","__MONOTONIC_TIMESTAMP":"1234567891","MESSAGE":"Test kernel warning"}'
echo '{"PRIORITY":"6","SYSLOG_IDENTIFIER":"kernel","_HOSTNAME":"raspberrypi","_BOOT_ID":"test-boot-id","__REALTIME_TIMESTAMP":"1709234567890125","__MONOTONIC_TIMESTAMP":"1234567892","MESSAGE":"Test kernel info"}'
sleep 1
`
	if err := os.WriteFile(mockPath, []byte(mockContent), 0755); err != nil {
		t.Fatalf("Failed to create mock journalctl: %v", err)
	}

	// Save original PATH
	oldPath := os.Getenv("PATH")

	// Modify PATH to find our mock command
	os.Setenv("PATH", tmpDir+":"+oldPath)

	// Return cleanup function
	return func() {
		os.Setenv("PATH", oldPath)
	}
}

func TestKernelLogForwarder(t *testing.T) {
	cleanup := createMockJournalctl(t)
	defer cleanup()

	logger, logs := logging.NewObservedTestLogger(t)

	cfg := utils.SystemConfiguration{
		ForwardKernelLogs: true,
	}

	k := NewKernelLogForwarder(logger, cfg)

	// On start, we should see kernel forwarder start log
	err := k.Start()
	test.That(t, err, test.ShouldBeNil)

	// Wait for logs to be output
	time.Sleep(100 * time.Millisecond)

	// Stop forwarding to ensure all logs are flushed
	err = k.Stop()
	test.That(t, err, test.ShouldBeNil)

	// Get the logs from the observed logger
	allLogs := logs.All()

	// Verify the logs
	test.That(t, len(allLogs), test.ShouldBeGreaterThan, 0)
	for _, log := range allLogs {
		test.That(t, log.Message, test.ShouldBeIn, []string{
			"Started Kernel logs forwarding",
			"[syslog_id=kernel boot_id=test-boot-id realtime=2024-02-29T19:22:47.890123Z monotonic=1.23456789s since boot] Test kernel error",
			"[syslog_id=kernel boot_id=test-boot-id realtime=2024-02-29T19:22:47.890124Z monotonic=1.234567891s since boot] Test kernel warning",
			"[syslog_id=kernel boot_id=test-boot-id realtime=2024-02-29T19:22:47.890125Z monotonic=1.234567892s since boot] Test kernel info",
			"Stopped Kernel logs forwarding",
		})
	}
}

func TestKernelLogForwarderDisabled(t *testing.T) {
	cleanup := createMockJournalctl(t)
	defer cleanup()

	logger, logs := logging.NewObservedTestLogger(t)
	cfg := utils.SystemConfiguration{
		ForwardKernelLogs: false,
	}
	k := NewKernelLogForwarder(logger, cfg)
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

	k := NewKernelLogForwarder(logger, cfg)

	// Start with forwarding disabled
	err := k.Start()
	test.That(t, err, test.ShouldBeNil)

	// Update to enable forwarding
	cfg.ForwardKernelLogs = true
	err = k.Update(cfg)
	test.That(t, err, test.ShouldBeNil)

	// Start with forwarding disabled
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

	k := NewKernelLogForwarder(logger, cfg)

	t.Run("command error", func(t *testing.T) {
		// Temporarily modify PATH to make journalctl unavailable
		oldPath := os.Getenv("PATH")
		os.Setenv("PATH", "")
		defer os.Setenv("PATH", oldPath)

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
