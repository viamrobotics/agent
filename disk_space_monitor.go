package agent

import (
	"context"
	"fmt"
	"time"

	"go.viam.com/rdk/logging"
	"go.viam.com/rdk/utils"
	"go.viam.com/rdk/utils/diskusage"
	goutils "go.viam.com/utils"
)

// diskSpaceCheckInterval is how often the disk space monitor checks for low disk space.
// This mirrors the viam-server disk monitor, reusing the same underlying diskusage logic to warn
// when the agent's install volume is running low on free space.
const diskSpaceCheckInterval = 5 * time.Minute

var isLowOnSpace = diskusage.IsLowOnSpace

type diskSpaceMonitor struct {
	path   string
	logger logging.Logger
	worker *goutils.StoppableWorkers
}

func newDiskSpaceMonitor(path string, logger logging.Logger) *diskSpaceMonitor {
	if path == "" {
		logger.Debug("no viam-agent path to watch; disk space monitor disabled")
		return nil
	}
	m := &diskSpaceMonitor{path: path, logger: logger}
	m.worker = goutils.NewBackgroundStoppableWorkers(func(ctx context.Context) {
		m.check(ctx)
		ticker := time.NewTicker(diskSpaceCheckInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.check(ctx)
			}
		}
	})
	return m
}

func (m *diskSpaceMonitor) check(ctx context.Context) {
	type result struct {
		usage diskusage.DiskUsage
		low   bool
		err   error
	}
	resCh := make(chan result, 1)
	goutils.PanicCapturingGo(func() {
		usage, low, err := isLowOnSpace(m.path)
		resCh <- result{usage: usage, low: low, err: err}
	})

	var res result
	select {
	case <-ctx.Done():
		return
	case res = <-resCh:
	}

	if res.err != nil {
		m.logger.Debugw("could not check free disk space", "path", m.path, "error", res.err)
		return
	}

	usedPercent := "unknown"
	if res.usage.SizeBytes > 0 {
		usedPercent = fmt.Sprintf("%.1f%%", (1-res.usage.AvailablePercent())*100)
	}

	if res.low {
		m.logger.Warnw("low free disk space",
			"path", m.path,
			"available", utils.FormatBytes(res.usage.AvailableBytes),
			"used", usedPercent,
			"threshold", fmt.Sprintf("%.0f%% used or <%s free",
				diskusage.MaxUsedFraction*100, utils.FormatBytes(diskusage.MinFreeBytes)))
	} else {
		m.logger.Debugw("free disk space",
			"path", m.path,
			"available", utils.FormatBytes(res.usage.AvailableBytes),
			"used", usedPercent)
	}
}

func (m *diskSpaceMonitor) stop() {
	if m == nil || m.worker == nil {
		return
	}
	m.worker.Stop()
}
