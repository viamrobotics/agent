package syscfg

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/viamrobotics/agent/utils"
	"go.uber.org/zap/zapcore"
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
trap exit TERM
# Initial entries
echo '{"PRIORITY":"3","SYSLOG_IDENTIFIER":"kernel","_HOSTNAME":"raspberrypi","_BOOT_ID":"test-boot-id","__REALTIME_TIMESTAMP":"1709234567890123","__MONOTONIC_TIMESTAMP":"1234567890","MESSAGE":"Test kernel error"}'
echo '{"PRIORITY":"4","SYSLOG_IDENTIFIER":"kernel","_HOSTNAME":"raspberrypi","_BOOT_ID":"test-boot-id","__REALTIME_TIMESTAMP":"1709234567890124","__MONOTONIC_TIMESTAMP":"1234567891","MESSAGE":"Test kernel warning"}'
echo '{"PRIORITY":"6","SYSLOG_IDENTIFIER":"kernel","_HOSTNAME":"raspberrypi","_BOOT_ID":"test-boot-id","__REALTIME_TIMESTAMP":"1709234567890125","__MONOTONIC_TIMESTAMP":"1234567892","MESSAGE":"Test kernel info"}'

# Sleep to simulate time passing
sleep 2

# Output new entries after delay
echo '{"PRIORITY":"6","SYSLOG_IDENTIFIER":"foobar","_PID":"666","_HOSTNAME":"raspberrypi","_BOOT_ID":"test-boot-id","__REALTIME_TIMESTAMP":"1709234567890133","__MONOTONIC_TIMESTAMP":"1234567892","MESSAGE":"Test foobar info"}'
echo '{"PRIORITY":"6","SYSLOG_IDENTIFIER":"NetworkManager","_PID":"555","_HOSTNAME":"raspberrypi","_BOOT_ID":"test-boot-id","__REALTIME_TIMESTAMP":"1709234567890134","__MONOTONIC_TIMESTAMP":"1234567892","MESSAGE":"New NetworkManager entry after forwarder started"}'
echo '{"PRIORITY":"6","SYSLOG_IDENTIFIER":"foobar","_PID":"666","_HOSTNAME":"raspberrypi","_BOOT_ID":"test-boot-id","__REALTIME_TIMESTAMP":"1709234567890135","__MONOTONIC_TIMESTAMP":"1234567892","MESSAGE":"Test foobar info"}'

# keep sleeping because journalctl should not exit
while true; do sleep 1; done
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

type mockAppender struct {
	mu      sync.Mutex
	entries []zapcore.Entry
}

func (m *mockAppender) Write(e zapcore.Entry, _ []zapcore.Field) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, e)
	return nil
}

func (m *mockAppender) Sync() error {
	return nil
}

func (m *mockAppender) All() []zapcore.Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.entries
}

func TestLogForwarderFilter(t *testing.T) {
	t.Cleanup(createMockJournalctl(t))
	ctx := t.Context()

	expectedEntries := map[string][]zapcore.Entry{
		"all,-foobar": {
			{
				Level:      zapcore.ErrorLevel,
				Time:       time.UnixMicro(1709234567890123),
				LoggerName: "kernel",
				Message:    "Test kernel error",
			},
			{
				Level:      zapcore.WarnLevel,
				Time:       time.UnixMicro(1709234567890124),
				LoggerName: "kernel",
				Message:    "Test kernel warning",
			},
			{
				Level:      zapcore.InfoLevel,
				Time:       time.UnixMicro(1709234567890125),
				LoggerName: "kernel",
				Message:    "Test kernel info",
			},
			{
				Level:      zapcore.InfoLevel,
				Time:       time.UnixMicro(1709234567890134),
				LoggerName: "NetworkManager[555]",
				Message:    "New NetworkManager entry after forwarder started",
			},
		},
		"kernel,NetworkManager": {
			{
				Level:      zapcore.ErrorLevel,
				Time:       time.UnixMicro(1709234567890123),
				LoggerName: "kernel",
				Message:    "Test kernel error",
			},
			{
				Level:      zapcore.WarnLevel,
				Time:       time.UnixMicro(1709234567890124),
				LoggerName: "kernel",
				Message:    "Test kernel warning",
			},
			{
				Level:      zapcore.InfoLevel,
				Time:       time.UnixMicro(1709234567890125),
				LoggerName: "kernel",
				Message:    "Test kernel info",
			},
			{
				Level:      zapcore.InfoLevel,
				Time:       time.UnixMicro(1709234567890134),
				LoggerName: "NetworkManager[555]",
				Message:    "New NetworkManager entry after forwarder started",
			},
		},
		"all": {
			{
				Level:      zapcore.ErrorLevel,
				Time:       time.UnixMicro(1709234567890123),
				LoggerName: "kernel",
				Message:    "Test kernel error",
			},
			{
				Level:      zapcore.WarnLevel,
				Time:       time.UnixMicro(1709234567890124),
				LoggerName: "kernel",
				Message:    "Test kernel warning",
			},
			{
				Level:      zapcore.InfoLevel,
				Time:       time.UnixMicro(1709234567890125),
				LoggerName: "kernel",
				Message:    "Test kernel info",
			},
			{
				Level:      zapcore.InfoLevel,
				Time:       time.UnixMicro(1709234567890133),
				LoggerName: "foobar[666]",
				Message:    "Test foobar info",
			},
			{
				Level:      zapcore.InfoLevel,
				Time:       time.UnixMicro(1709234567890134),
				LoggerName: "NetworkManager[555]",
				Message:    "New NetworkManager entry after forwarder started",
			},
			{
				Level:      zapcore.InfoLevel,
				Time:       time.UnixMicro(1709234567890135),
				LoggerName: "foobar[666]",
				Message:    "Test foobar info",
			},
		},
		"": []zapcore.Entry(nil),
	}

	for cfgVal, expected := range expectedEntries {
		testName := cfgVal
		if testName == "" {
			testName = "NONE"
		}
		t.Run(testName, func(t *testing.T) {
			cfg := utils.AgentConfig{
				SystemConfiguration: utils.SystemConfiguration{
					ForwardSystemLogs:                     cfgVal,
					LoggingJournaldSystemMaxUseMegabytes:  -1,
					LoggingJournaldRuntimeMaxUseMegabytes: -1,
				},
			}

			logger, logs := logging.NewObservedTestLogger(t)

			appender := &mockAppender{}

			sys := NewSubsystem(ctx, logger, cfg, func() logging.Appender {
				return appender
			})

			// On start, we should see kernel forwarder start log
			err := sys.Start(t.Context())
			test.That(t, err, test.ShouldBeNil)

			// Wait for initial logs
			time.Sleep(100 * time.Millisecond)

			// Verify initial forwarded entries
			initialEntries := 3
			if cfgVal == "" {
				initialEntries = 0
			}

			test.That(t, len(appender.All()), test.ShouldEqual, initialEntries)

			// Wait for new logs
			time.Sleep(3 * time.Second)

			// Stop forwarding to ensure all logs are flushed
			err = sys.Stop(t.Context())
			test.That(t, err, test.ShouldBeNil)

			// Verify total forwarded entries
			test.That(t, len(appender.All()), test.ShouldEqual, len(expected))

			// Verify forwarded entries content
			test.That(t, appender.All(), test.ShouldResemble, expected)

			// Verify the logs in order
			expectedLogs := []string{
				"Starting syscfg",
				"Started system log forwarding",
				"stopped journalctl",
				"Stopped system log forwarding",
			}

			for i, log := range logs.All() {
				test.That(t, log.Message, test.ShouldEqual, expectedLogs[i])
				// bail after the first line when we're disabled
				if cfgVal == "" {
					break
				}
			}
		})
	}
}
