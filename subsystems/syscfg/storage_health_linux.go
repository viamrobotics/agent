package syscfg

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const storageHealthInterval = 15 * time.Minute

// ext4SysfsDir is a var so tests can point it at a fake sysfs.
var ext4SysfsDir = "/sys/fs/ext4"

type ext4Errors struct {
	count     int
	firstTime time.Time
	lastTime  time.Time
}

// startStorageHealth periodically reports ext4 error counters. SD cards have no SMART data, so
// these are the best available signal that the media is failing.
func (s *Subsystem) startStorageHealth(ctx context.Context) {
	if s.storageCancel != nil {
		return
	}

	storageCtx, cancel := context.WithCancel(ctx)
	s.storageCancel = cancel

	s.storageWorker.Go(func() {
		reported := map[string]int{}
		ticker := time.NewTicker(storageHealthInterval)
		defer ticker.Stop()
		for {
			s.checkExt4Errors(reported)
			select {
			case <-storageCtx.Done():
				return
			case <-ticker.C:
			}
		}
	})
}

func (s *Subsystem) stopStorageHealth() {
	cancel := s.storageCancel
	s.storageCancel = nil

	if cancel != nil {
		cancel()
		s.storageWorker.Wait()
	}
}

// checkExt4Errors logs each filesystem whose error count is nonzero and higher than last reported.
func (s *Subsystem) checkExt4Errors(reported map[string]int) {
	all, err := readExt4Errors(ext4SysfsDir)
	if err != nil {
		s.logger.Debugw("reading ext4 error counters", "error", err)
		return
	}
	for dev, e := range all {
		if e.count == 0 || e.count <= reported[dev] {
			continue
		}
		reported[dev] = e.count
		s.logger.Errorw("filesystem has recorded errors, storage may be failing",
			"device", dev,
			"errors_count", e.count,
			"first_error_time", e.firstTime,
			"last_error_time", e.lastTime,
		)
	}
}

func readExt4Errors(dir string) (map[string]ext4Errors, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return map[string]ext4Errors{}, nil
		}
		return nil, err
	}

	out := map[string]ext4Errors{}
	for _, entry := range entries {
		devDir := filepath.Join(dir, entry.Name())
		count, err := readSysfsInt(filepath.Join(devDir, "errors_count"))
		if err != nil {
			// not a filesystem directory (e.g. "features")
			continue
		}
		e := ext4Errors{count: int(count)}
		// times are unix seconds, 0 when unset
		if t, err := readSysfsInt(filepath.Join(devDir, "first_error_time")); err == nil && t > 0 {
			e.firstTime = time.Unix(t, 0)
		}
		if t, err := readSysfsInt(filepath.Join(devDir, "last_error_time")); err == nil && t > 0 {
			e.lastTime = time.Unix(t, 0)
		}
		out[entry.Name()] = e
	}
	return out, nil
}

func readSysfsInt(path string) (int64, error) {
	//nolint:gosec
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
}
