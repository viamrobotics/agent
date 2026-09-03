package agent

import (
	"context"
	"errors"
	"testing"

	"go.uber.org/zap/zapcore"
	"go.viam.com/rdk/logging"
	"go.viam.com/rdk/utils/diskusage"
	"go.viam.com/test"
)

func TestNewDiskSpaceMonitor(t *testing.T) {
	t.Run("empty path disables monitor", func(t *testing.T) {
		logger := logging.NewTestLogger(t)
		m := newDiskSpaceMonitor("", logger)
		test.That(t, m, test.ShouldBeNil)
	})

	t.Run("non-empty path creates monitor", func(t *testing.T) {
		logger := logging.NewTestLogger(t)
		m := newDiskSpaceMonitor(t.TempDir(), logger)
		test.That(t, m, test.ShouldNotBeNil)
		m.stop()
	})
}

func TestDiskSpaceMonitorCheck(t *testing.T) {
	t.Run("healthy disk logs debug", func(t *testing.T) {
		isLowOnSpace := func(string) (diskusage.DiskUsage, bool, error) {
			return diskusage.DiskUsage{AvailableBytes: 5 * 1024 * 1024, SizeBytes: 10 * 1024 * 1024}, false, nil
		}

		logger, logs := logging.NewObservedTestLogger(t)
		m := &diskSpaceMonitor{path: t.TempDir(), logger: logger, isLowOnSpace: isLowOnSpace}

		m.check(context.Background())

		test.That(t, logs.FilterMessage("free disk space").FilterLevelExact(zapcore.DebugLevel).Len(), test.ShouldEqual, 1)
	})

	t.Run("low disk logs warning", func(t *testing.T) {
		isLowOnSpace := func(string) (diskusage.DiskUsage, bool, error) {
			return diskusage.DiskUsage{AvailableBytes: 1, SizeBytes: 100}, true, nil
		}

		logger, logs := logging.NewObservedTestLogger(t)
		m := &diskSpaceMonitor{path: t.TempDir(), logger: logger, isLowOnSpace: isLowOnSpace}

		m.check(context.Background())

		test.That(t, logs.FilterMessage("low free disk space").FilterLevelExact(zapcore.WarnLevel).Len(), test.ShouldEqual, 1)
	})

	t.Run("disk error is logged at debug and does not fail", func(t *testing.T) {
		isLowOnSpace := func(string) (diskusage.DiskUsage, bool, error) {
			return diskusage.DiskUsage{}, false, errors.New("boom")
		}

		logger, logs := logging.NewObservedTestLogger(t)
		m := &diskSpaceMonitor{path: t.TempDir(), logger: logger, isLowOnSpace: isLowOnSpace}

		test.That(t, func() { m.check(context.Background()) }, test.ShouldNotPanic)
		test.That(t, logs.FilterMessage("could not check free disk space").FilterLevelExact(zapcore.DebugLevel).Len(), test.ShouldEqual, 1)
	})
}

func TestDiskSpaceMonitorStop(t *testing.T) {
	t.Run("nil monitor does not panic", func(t *testing.T) {
		var m *diskSpaceMonitor
		test.That(t, func() { m.stop() }, test.ShouldNotPanic)
	})

	t.Run("empty worker is safe", func(t *testing.T) {
		m := &diskSpaceMonitor{}
		test.That(t, func() { m.stop() }, test.ShouldNotPanic)
	})
}
