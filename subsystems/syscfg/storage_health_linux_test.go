package syscfg

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"go.viam.com/rdk/logging"
	"go.viam.com/test"
)

func writeExt4Fs(t *testing.T, dir, dev, count, first, last string) {
	t.Helper()
	devDir := filepath.Join(dir, dev)
	test.That(t, os.MkdirAll(devDir, 0o755), test.ShouldBeNil)
	for name, val := range map[string]string{"errors_count": count, "first_error_time": first, "last_error_time": last} {
		test.That(t, os.WriteFile(filepath.Join(devDir, name), []byte(val+"\n"), 0o644), test.ShouldBeNil)
	}
}

func TestReadExt4Errors(t *testing.T) {
	dir := t.TempDir()
	writeExt4Fs(t, dir, "mmcblk0p2", "3", "1700000000", "1700000100")
	writeExt4Fs(t, dir, "sda1", "0", "0", "0")
	test.That(t, os.MkdirAll(filepath.Join(dir, "features"), 0o755), test.ShouldBeNil)

	got, err := readExt4Errors(dir)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, got, test.ShouldResemble, map[string]ext4Errors{
		"mmcblk0p2": {count: 3, firstTime: time.Unix(1700000000, 0), lastTime: time.Unix(1700000100, 0)},
		"sda1":      {},
	})

	got, err = readExt4Errors(filepath.Join(dir, "missing"))
	test.That(t, err, test.ShouldBeNil)
	test.That(t, got, test.ShouldBeEmpty)
}

func TestCheckExt4Errors(t *testing.T) {
	dir := t.TempDir()
	orig := ext4SysfsDir
	ext4SysfsDir = dir
	t.Cleanup(func() { ext4SysfsDir = orig })

	logger, logs := logging.NewObservedTestLogger(t)
	reported := map[string]int{}
	msg := "filesystem has recorded errors, storage may be failing"

	writeExt4Fs(t, dir, "mmcblk0p2", "0", "0", "0")
	checkExt4Errors(logger, reported)
	test.That(t, logs.FilterMessage(msg).Len(), test.ShouldEqual, 0)

	writeExt4Fs(t, dir, "mmcblk0p2", "1", "1700000000", "1700000000")
	checkExt4Errors(logger, reported)
	test.That(t, logs.FilterMessage(msg).Len(), test.ShouldEqual, 1)

	// unchanged count is not re-reported
	checkExt4Errors(logger, reported)
	test.That(t, logs.FilterMessage(msg).Len(), test.ShouldEqual, 1)

	writeExt4Fs(t, dir, "mmcblk0p2", "2", "1700000000", "1700000100")
	checkExt4Errors(logger, reported)
	test.That(t, logs.FilterMessage(msg).Len(), test.ShouldEqual, 2)
}
