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

// testLogger captures log messages for verification
type testLogger struct {
	logging.Logger
	messages []string
}

func (l *testLogger) Error(args ...interface{}) {
	l.messages = append(l.messages, "ERROR: "+fmt.Sprint(args...))
	l.Logger.Error(args...)
}

func (l *testLogger) Info(args ...interface{}) {
	l.messages = append(l.messages, "INFO: "+fmt.Sprint(args...))
	l.Logger.Info(args...)
}

func (l *testLogger) GetMessages() []string {
	return l.messages
}

// createMockJournalctl creates a temporary mock journalctl command that outputs test logs
func createMockJournalctl(t *testing.T) (string, func()) {
	// Create a temporary directory for the mock command
	tmpDir, err := os.MkdirTemp("", "mock-journalctl")
	assert.NoError(t, err)

	// Create the mock command
	mockPath := filepath.Join(tmpDir, "journalctl")
	mockContent := `#!/bin/bash
echo '{"MESSAGE":"Test kernel error","PRIORITY":3}'
echo '{"MESSAGE":"Test kernel warning","PRIORITY":4}'
echo '{"MESSAGE":"Test kernel info","PRIORITY":6}'
sleep 1
`
	err = os.WriteFile(mockPath, []byte(mockContent), 0755)
	assert.NoError(t, err)

	// Add the temporary directory to PATH
	oldPath := os.Getenv("PATH")
	os.Setenv("PATH", tmpDir+":"+oldPath)

	// Return cleanup function
	cleanup := func() {
		os.Setenv("PATH", oldPath)
		os.RemoveAll(tmpDir)
	}

	return mockPath, cleanup
}

func TestKernelLogForwarder(t *testing.T) {
	logger := &testLogger{
		Logger:   logging.NewTestLogger(t),
		messages: make([]string, 0),
	}

	tests := []struct {
		name     string
		cfg      utils.SystemConfiguration
		action   func(*KernelLogForwarder) error
		expected []string
	}{
		{
			name: "start when not running",
			cfg: utils.SystemConfiguration{
				ForwardKernelLogs: true,
			},
			action: func(k *KernelLogForwarder) error {
				return k.Start()
			},
			expected: []string{
				"INFO: Started Kernel logs forwarding",
			},
		},
		{
			name: "stop when running",
			cfg: utils.SystemConfiguration{
				ForwardKernelLogs: true,
			},
			action: func(k *KernelLogForwarder) error {
				if err := k.Start(); err != nil {
					return err
				}
				time.Sleep(100 * time.Millisecond) // Wait for process to start
				return k.Stop()
			},
			expected: []string{
				"INFO: Started Kernel logs forwarding",
				"INFO: Stopped Kernel logs forwarding",
			},
		},
		{
			name: "update configuration",
			cfg: utils.SystemConfiguration{
				ForwardKernelLogs: true,
			},
			action: func(k *KernelLogForwarder) error {
				if err := k.Start(); err != nil {
					return err
				}
				time.Sleep(100 * time.Millisecond) // Wait for process to start
				k.cfg.ForwardKernelLogs = false
				return k.Start()
			},
			expected: []string{
				"INFO: Started Kernel logs forwarding",
				"INFO: Stopped Kernel logs forwarding",
			},
		},
		{
			name: "update with no change",
			cfg: utils.SystemConfiguration{
				ForwardKernelLogs: true,
			},
			action: func(k *KernelLogForwarder) error {
				if err := k.Start(); err != nil {
					return err
				}
				time.Sleep(100 * time.Millisecond) // Wait for process to start
				return k.Start()
			},
			expected: []string{
				"INFO: Started Kernel logs forwarding",
			},
		},
		{
			name: "concurrent access",
			cfg: utils.SystemConfiguration{
				ForwardKernelLogs: true,
			},
			action: func(k *KernelLogForwarder) error {
				// Start the forwarder
				if err := k.Start(); err != nil {
					return err
				}
				time.Sleep(100 * time.Millisecond) // Wait for process to start

				// Simulate concurrent updates
				done := make(chan error)
				for i := 0; i < 5; i++ {
					go func() {
						k.cfg.ForwardKernelLogs = !k.cfg.ForwardKernelLogs
						done <- k.Start()
					}()
				}

				// Wait for all goroutines to complete
				for i := 0; i < 5; i++ {
					if err := <-done; err != nil {
						return err
					}
				}
				return nil
			},
			expected: []string{
				"INFO: Started Kernel logs forwarding",
				"INFO: Stopped Kernel logs forwarding",
				"INFO: Started Kernel logs forwarding",
				"INFO: Stopped Kernel logs forwarding",
				"INFO: Started Kernel logs forwarding",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			k := NewKernelLogForwarder(logger, tc.cfg)
			err := tc.action(k)
			assert.NoError(t, err)

			// Verify log messages
			messages := logger.GetMessages()
			assert.Equal(t, tc.expected, messages)

			// Clean up
			if err := k.Stop(); err != nil {
				t.Logf("Error stopping forwarder: %v", err)
			}
		})
	}
}

func TestKernelLogForwarderErrorHandling(t *testing.T) {
	logger := &testLogger{
		Logger:   logging.NewTestLogger(t),
		messages: make([]string, 0),
	}

	tests := []struct {
		name     string
		cfg      utils.SystemConfiguration
		action   func(*KernelLogForwarder) error
		expected []string
	}{
		{
			name: "command error",
			cfg: utils.SystemConfiguration{
				ForwardKernelLogs: true,
			},
			action: func(k *KernelLogForwarder) error {
				// Temporarily set PATH to make journalctl unavailable
				oldPath := os.Getenv("PATH")
				os.Setenv("PATH", "")
				defer os.Setenv("PATH", oldPath)
				return k.Start()
			},
			expected: []string{
				"ERROR: journalctl not available, kernel log forwarding disabled",
			},
		},
		{
			name: "stop after context cancellation",
			cfg: utils.SystemConfiguration{
				ForwardKernelLogs: true,
			},
			action: func(k *KernelLogForwarder) error {
				if err := k.Start(); err != nil {
					return err
				}
				time.Sleep(100 * time.Millisecond) // Wait for process to start
				k.cancel()
				return k.Stop()
			},
			expected: []string{
				"INFO: Started Kernel logs forwarding",
				"INFO: Stopped Kernel logs forwarding",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			k := NewKernelLogForwarder(logger, tc.cfg)
			err := tc.action(k)
			assert.NoError(t, err)

			// Verify log messages
			messages := logger.GetMessages()
			assert.Equal(t, tc.expected, messages)

			// Clean up
			if err := k.Stop(); err != nil {
				t.Logf("Error stopping forwarder: %v", err)
			}
		})
	}
}

func TestKernelLogForwarderForwarding(t *testing.T) {
	logger := &testLogger{
		Logger:   logging.NewTestLogger(t),
		messages: make([]string, 0),
	}

	// Create mock journalctl command
	_, cleanup := createMockJournalctl(t)
	defer cleanup()

	k := NewKernelLogForwarder(logger, utils.SystemConfiguration{
		ForwardKernelLogs: true,
	})

	// Start the forwarder
	err := k.Start()
	assert.NoError(t, err)

	// Wait for logs to be processed
	time.Sleep(2 * time.Second)

	// Stop the forwarder
	err = k.Stop()
	assert.NoError(t, err)

	// Verify that the test messages were captured
	messages := logger.GetMessages()
	assert.Contains(t, messages, "Test kernel error")
	assert.Contains(t, messages, "Test kernel warning")
	assert.Contains(t, messages, "Test kernel info")
}
