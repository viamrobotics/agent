package utils

import (
	"context"
	"time"

	errw "github.com/pkg/errors"
	"go.viam.com/rdk/logging"
	"golang.org/x/sys/unix"
)

func systemBootTime() (time.Time, error) {
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return time.Time{}, errw.Wrap(err, "reading kern.boottime")
	}
	return time.Unix(tv.Unix()), nil
}

func systemIsShuttingDown(_ context.Context, _ logging.Logger) bool {
	// launchd gives no equivalent of systemd's system state.
	return false
}
