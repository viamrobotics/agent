package syscfg

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
)

// testLogger is a custom logger that captures messages for testing
type testLogger struct {
	logging.Logger
	messages []string
}

func (l *testLogger) Error(args ...interface{}) {
	msg := fmt.Sprint(args...)
	l.messages = append(l.messages, msg)
	l.Logger.Error(args...)
}

func (l *testLogger) Info(args ...interface{}) {
	msg := fmt.Sprint(args...)
	l.messages = append(l.messages, msg)
	l.Logger.Info(args...)
}

func (l *testLogger) Write(entry *logging.LogEntry) {
	msg := entry.Message
	l.messages = append(l.messages, msg)
	l.Logger.Write(entry)
}

func (l *testLogger) GetMessages() []string {
	return l.messages
}

// createMockJournalctl creates a temporary mock journalctl command that outputs test logs
func createMockJournalctl(t *testing.T) (string, func()) {
	// Create a temporary directory for our mock command
	tmpDir := t.TempDir()
	mockPath := filepath.Join(tmpDir, "journalctl")

	// Create the mock command script
	script := `#!/bin/sh
echo '{"PRIORITY": "3", "MESSAGE": "Test kernel error", "SYSLOG_FACILITY": "0", "SYSLOG_IDENTIFIER": "kernel"}'
echo '{"PRIORITY": "4", "MESSAGE": "Test kernel warning", "SYSLOG_FACILITY": "0", "SYSLOG_IDENTIFIER": "kernel"}'
echo '{"PRIORITY": "6", "MESSAGE": "Test kernel info", "SYSLOG_FACILITY": "0", "SYSLOG_IDENTIFIER": "kernel"}'
sleep 1
`
	err := os.WriteFile(mockPath, []byte(script), 0755)
	assert.NoError(t, err)

	// Save original PATH and modify it to include our mock command
	originalPath := os.Getenv("PATH")
	os.Setenv("PATH", tmpDir+":"+originalPath)

	// Return cleanup function
	cleanup := func() {
		os.Setenv("PATH", originalPath)
	}

	return mockPath, cleanup
}

func TestKernelLogForwarder(t *testing.T) {
	logger := &testLogger{
		Logger: logging.NewTestLogger(t),
	}

	t.Run("start and stop", func(t *testing.T) {
		cfg := utils.SystemConfiguration{
			ForwardKernelLogs: true,
		}
		forwarder := NewKernelLogForwarder(logger, cfg)

		// Start should succeed
		err := forwarder.Start()
		assert.NoError(t, err)

		// Wait a bit to ensure the command is running
		time.Sleep(100 * time.Millisecond)

		// Stop should succeed
		err = forwarder.Stop()
		assert.NoError(t, err)
	})

	t.Run("start when disabled", func(t *testing.T) {
		cfg := utils.SystemConfiguration{
			ForwardKernelLogs: false,
		}
		forwarder := NewKernelLogForwarder(logger, cfg)

		err := forwarder.Start()
		// Start should succeed but do nothing
		assert.NoError(t, err)
		assert.Nil(t, forwarder.cmd)
	})

	t.Run("stop when not running", func(t *testing.T) {
		cfg := utils.SystemConfiguration{
			ForwardKernelLogs: true,
		}
		forwarder := NewKernelLogForwarder(logger, cfg)

		err := forwarder.Stop()
		assert.NoError(t, err)
	})

	t.Run("update configuration", func(t *testing.T) {
		cfg := utils.SystemConfiguration{
			ForwardKernelLogs: true,
		}
		forwarder := NewKernelLogForwarder(logger, cfg)

		// Start should succeed
		err := forwarder.Start()
		assert.NoError(t, err)

		// Wait a bit to ensure the command is running
		time.Sleep(100 * time.Millisecond)

		// Update to disable forwarding
		newCfg := utils.SystemConfiguration{
			ForwardKernelLogs: false,
		}
		err = forwarder.Update(newCfg)
		assert.NoError(t, err)
		assert.Nil(t, forwarder.cmd)

		// Update to enable forwarding again
		newCfg.ForwardKernelLogs = true
		err = forwarder.Update(newCfg)
		assert.NoError(t, err)
		assert.NotNil(t, forwarder.cmd)

		// Clean up
		err = forwarder.Stop()
		assert.NoError(t, err)
	})

	t.Run("update with no change", func(t *testing.T) {
		cfg := utils.SystemConfiguration{
			ForwardKernelLogs: true,
		}
		forwarder := NewKernelLogForwarder(logger, cfg)

		// Start should succeed
		err := forwarder.Start()
		assert.NoError(t, err)

		// Wait a bit to ensure the command is running
		time.Sleep(100 * time.Millisecond)

		// Update with same config should not restart
		err = forwarder.Update(cfg)
		assert.NoError(t, err)
		assert.NotNil(t, forwarder.cmd)

		// Clean up
		err = forwarder.Stop()
		assert.NoError(t, err)
	})

	t.Run("forward kernel logs", func(t *testing.T) {
		// Create mock journalctl command
		_, cleanup := createMockJournalctl(t)
		defer cleanup()

		cfg := utils.SystemConfiguration{
			ForwardKernelLogs: true,
		}
		forwarder := NewKernelLogForwarder(logger, cfg)

		// Start the forwarder
		err := forwarder.Start()
		assert.NoError(t, err)
		assert.NotNil(t, forwarder.cmd)

		// Wait for logs to be processed
		time.Sleep(2 * time.Second)

		// Stop the forwarder
		err = forwarder.Stop()
		assert.NoError(t, err)

		// Verify that the logs were captured
		messages := logger.GetMessages()
		assert.Contains(t, messages, "Test kernel error")
		assert.Contains(t, messages, "Test kernel warning")
		assert.Contains(t, messages, "Test kernel info")
	})
}

func TestKernelLogForwarderErrorHandling(t *testing.T) {
	logger := &testLogger{
		Logger: logging.NewTestLogger(t),
	}

	t.Run("command error", func(t *testing.T) {
		// Temporarily modify PATH to make journalctl unavailable
		originalPath := os.Getenv("PATH")
		os.Setenv("PATH", "")
		defer os.Setenv("PATH", originalPath)

		cfg := utils.SystemConfiguration{
			ForwardKernelLogs: true,
		}
		forwarder := NewKernelLogForwarder(logger, cfg)

		err := forwarder.Start()
		assert.NoError(t, err)
		assert.Nil(t, forwarder.cmd)

		// Verify that an error was logged
		messages := logger.GetMessages()
		assert.Contains(t, messages, "journalctl not available, kernel log forwarding disabled")
	})
}
