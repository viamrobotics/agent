package syscfg

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"go.viam.com/rdk/logging"
	"go.viam.com/test"
)

func TestUpgradeState(t *testing.T) {
	var state upgradeState
	test.That(t, state.running(), test.ShouldBeFalse)

	done := state.begin()
	test.That(t, state.running(), test.ShouldBeTrue)

	done()
	test.That(t, state.running(), test.ShouldBeFalse)
}

// testPendingUpdates covers a fully populated update and one where the package
// manager reported nothing but a name.
var testPendingUpdates = []pendingUpdate{
	{
		Name:           "libc6",
		CurrentVersion: "2.36-9+deb12u7",
		Version:        "2.36-9+deb12u10",
		DownloadSize:   2799652,
		InstalledSize:  13065216,
		Category:       "security",
	},
	{Name: "2024-01 Cumulative Update for Windows 11 (KB5034123)"},
}

// newObservedLogger returns a logger that both records its entries and renders them
// the way the console and file appenders a device actually logs through do, so
// tests can assert on the structured fields and on the resulting log line.
func newObservedLogger(t *testing.T) (logging.Logger, *observer.ObservedLogs, *bytes.Buffer) {
	t.Helper()
	logger, logs := logging.NewObservedTestLogger(t)
	var output bytes.Buffer
	logger.AddAppender(logging.NewWriterAppender(&output))
	return logger, logs, &output
}

// TestPendingUpdatesAreLoggable checks that the logger can render a
// []pendingUpdate, which the log sites hand over as a single value for zap to
// format by reflection. A value zap can't format would otherwise turn the one log
// line that says what is being installed into a placeholder.
func TestPendingUpdatesAreLoggable(t *testing.T) {
	logger, logs, output := newObservedLogger(t)
	logPendingUpdates(logger, updateSummary{updates: testPendingUpdates}, "package_manager", "apt")

	entries := logs.All()
	test.That(t, entries, test.ShouldHaveLength, 1)
	test.That(t, entries[0].Level, test.ShouldEqual, zapcore.InfoLevel)
	test.That(t, entries[0].ContextMap()["activity"], test.ShouldEqual, "system")
	test.That(t, entries[0].ContextMap()["event"], test.ShouldEqual, updateActivityStart)
	test.That(t, entries[0].ContextMap()["updates"], test.ShouldResemble, testPendingUpdates)
	test.That(t, entries[0].ContextMap()["package_manager"], test.ShouldEqual, "apt")

	// Fields that fail to serialize are quietly replaced with a "logging_err" field
	// rather than failing the write, so assert the rendered line carries the detail.
	line := output.String()
	test.That(t, line, test.ShouldNotContainSubstring, "logging_err")
	test.That(t, line, test.ShouldContainSubstring, `"name":"libc6"`)
	test.That(t, line, test.ShouldContainSubstring, `"version":"2.36-9+deb12u10"`)
	test.That(t, line, test.ShouldContainSubstring, `"current_version":"2.36-9+deb12u7"`)
	test.That(t, line, test.ShouldContainSubstring, `"download_size":2799652`)
	test.That(t, line, test.ShouldContainSubstring, `"installed_size":13065216`)
	test.That(t, line, test.ShouldContainSubstring, `"category":"security"`)
	test.That(t, line, test.ShouldContainSubstring, "KB5034123")

	// Fields the package manager didn't report are left out entirely.
	test.That(t, line, test.ShouldNotContainSubstring, `"version":""`)
	test.That(t, line, test.ShouldNotContainSubstring, `"download_size":0`)
	test.That(t, line, test.ShouldNotContainSubstring, `"category":""`)
}

func TestLogPendingUpdates(t *testing.T) {
	t.Run("nothing pending", func(t *testing.T) {
		logger, logs, _ := newObservedLogger(t)
		logPendingUpdates(logger, updateSummary{})

		entries := logs.All()
		test.That(t, entries, test.ShouldHaveLength, 1)
		test.That(t, entries[0].Level, test.ShouldEqual, zapcore.InfoLevel)
		test.That(t, entries[0].Message, test.ShouldEqual, "No OS updates pending, nothing to install")
	})

	t.Run("listing failed", func(t *testing.T) {
		logger, logs, output := newObservedLogger(t)
		logPendingUpdates(logger, updateSummary{listErr: errors.New("apt-get exploded")})

		entries := logs.All()
		test.That(t, entries, test.ShouldHaveLength, 1)
		// A failed listing is a warning: the upgrade still runs, but we've lost the
		// record of what it installs.
		test.That(t, entries[0].Level, test.ShouldEqual, zapcore.InfoLevel)
		test.That(t, entries[0].LoggerName, test.ShouldEndWith, ".activity")
		test.That(t, output.String(), test.ShouldContainSubstring, "apt-get exploded")
	})
}

func TestLogUpgradeResult(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		logger, logs, output := newObservedLogger(t)
		logUpgradeResult(t.Context(), logger, testPendingUpdates, nil, "security_only", true)

		entries := logs.All()
		test.That(t, entries, test.ShouldHaveLength, 1)
		test.That(t, entries[0].ContextMap()["activity"], test.ShouldEqual, "system")
		test.That(t, entries[0].ContextMap()["event"], test.ShouldEqual, updateActivityComplete)
		test.That(t, entries[0].ContextMap()["updates"], test.ShouldResemble, testPendingUpdates)
		test.That(t, entries[0].ContextMap()["security_only"], test.ShouldEqual, true)
		test.That(t, output.String(), test.ShouldContainSubstring, `"name":"libc6"`)
	})

	t.Run("failure", func(t *testing.T) {
		logger, logs, output := newObservedLogger(t)
		logUpgradeResult(t.Context(), logger, testPendingUpdates, errors.New("dpkg failed"))

		entries := logs.All()
		test.That(t, entries, test.ShouldHaveLength, 1)
		test.That(t, entries[0].ContextMap()["activity"], test.ShouldEqual, "system")
		test.That(t, entries[0].ContextMap()["event"], test.ShouldEqual, updateActivityFail)
		// The failed run still reports what it managed to install.
		test.That(t, output.String(), test.ShouldContainSubstring, `"name":"libc6"`)
		test.That(t, output.String(), test.ShouldContainSubstring, "dpkg failed")
	})

	t.Run("interrupted by shutdown", func(t *testing.T) {
		logger, logs, _ := newObservedLogger(t)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		logUpgradeResult(ctx, logger, testPendingUpdates, errors.New("signal: killed"))

		entries := logs.All()
		test.That(t, entries, test.ShouldHaveLength, 1)
		// The agent killed the upgrade itself, so this is an abort, not a failure.
		test.That(t, entries[0].ContextMap()["activity"], test.ShouldEqual, "system")
		test.That(t, entries[0].ContextMap()["event"], test.ShouldEqual, updateActivityAbort)
	})

	t.Run("installed packages unknown", func(t *testing.T) {
		logger, logs, _ := newObservedLogger(t)
		logUpgradeResult(t.Context(), logger, nil, nil, "security_only", true)

		entries := logs.All()
		test.That(t, entries, test.ShouldHaveLength, 1)
		test.That(t, entries[0].ContextMap()["event"], test.ShouldEqual, updateActivityComplete)
		// With no report of what was installed, the list is omitted entirely rather
		// than logged as empty; the start entry already says what was pending.
		_, present := entries[0].ContextMap()["updates"]
		test.That(t, present, test.ShouldBeFalse)
		test.That(t, entries[0].ContextMap()["security_only"], test.ShouldEqual, true)
	})
}

func TestParseSize(t *testing.T) {
	for _, tc := range []struct {
		size     string
		expected uint64
	}{
		{"2799652", 2799652},
		{"0", 0},
		{"1.4 M", 1468006},
		{"1.4M", 1468006},
		{"1.4 MiB", 1468006},
		{"108MB", 113246208},
		{" 12 k ", 12288},
		{"3.5 G", 3758096384},
		{"2 T", 2199023255552},
		// Unparseable sizes read as "unknown" rather than a wrong number.
		{"", 0},
		{"unknown", 0},
		{"-5 M", 0},
	} {
		test.That(t, parseSize(tc.size), test.ShouldEqual, tc.expected)
	}
}
