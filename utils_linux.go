package agent

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	errw "github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// platform-specific UID check.
func checkPathOwner(uid int, info fs.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		// should be impossible on Linux
		return errw.New("cannot convert to syscall.Stat_t")
	}
	if uid != int(stat.Uid) {
		return errw.Errorf("%s is owned by UID %d but the current UID is %d", info.Name(), stat.Uid, uid)
	}
	return nil
}

func SyncFS(syncPath string) (errRet error) {
	file, errRet := os.Open(filepath.Dir(syncPath))
	if errRet != nil {
		return errw.Wrapf(errRet, "syncing fs %s", syncPath)
	}
	_, _, err := unix.Syscall(unix.SYS_SYNCFS, file.Fd(), 0, 0)
	if err != 0 {
		errRet = errw.Wrapf(err, "syncing fs %s", syncPath)
	}
	return errors.Join(errRet, file.Close())
}

func RequestRestart() error {
	return nil
}
