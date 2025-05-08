package utils

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	errw "github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

func PlatformProcSettings(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// KillTree sends SIGKILL to the process group.
func KillTree(pid int) error {
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil {
		return errw.Wrapf(err, "killing PID %d", pid)
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

func writePlatformOutput(p []byte) (int, error) {
	return os.Stdout.Write(p)
}

func SignalForTermination(pid int) error {
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return errw.Wrapf(err, "signaling PID %d", pid)
	}
	return nil
}
