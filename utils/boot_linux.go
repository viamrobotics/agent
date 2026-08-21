package utils

import (
	"context"
	"os/exec"
	"strings"
	"time"

	errw "github.com/pkg/errors"
	"go.viam.com/rdk/logging"
	"golang.org/x/sys/unix"
)

func systemBootTime() (time.Time, error) {
	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return time.Time{}, errw.Wrap(err, "getting sysinfo")
	}
	// Uptime is int32 on 32 bit platforms and int64 on 64 bit ones; converting to a
	// Duration handles both.
	return time.Now().Add(-time.Duration(info.Uptime) * time.Second), nil
}

func systemIsShuttingDown(ctx context.Context, logger logging.Logger) bool {
	// systemctl exits non-zero for every state other than "running", so only the
	// output matters here.
	output, err := exec.CommandContext(ctx, "systemctl", "is-system-running").Output()
	if err != nil && len(output) == 0 {
		logger.Debugw("cannot determine system state", "err", err)
		return false
	}
	return strings.TrimSpace(string(output)) == "stopping"
}
