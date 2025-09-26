package utils

import (
	"io/fs"
	"os"
	"os/exec"
	"strconv"
	"syscall"

	errw "github.com/pkg/errors"
	goutils "go.viam.com/utils"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

func PlatformProcSettings(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
}

// KillTree kills the process group.
func KillTree(pid int) error {
	//nolint:gosec
	cmd := exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(pid))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return errw.Wrapf(err, "killing PID %d: %s", pid, out)
	}
	return nil
}

// platform-specific UID check.
func checkPathOwner(_ int, _ fs.FileInfo) error {
	// todo(windows)
	return nil
}

func SyncFS(syncPath string) error {
	handle, err := syscall.Open(syncPath, syscall.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() {
		goutils.UncheckedError(syscall.CloseHandle(handle))
	}()
	err = syscall.Fsync(handle)
	if err != nil {
		return err
	}
	return nil
}

func SignalForTermination(pid int) error {
	return windows.GenerateConsoleCtrlEvent(syscall.CTRL_BREAK_EVENT, uint32(pid)) //nolint:gosec
}

// SignalForQuit is the same as SignalForTermination on Windows for now.
func SignalForQuit(pid int) error {
	return SignalForTermination(pid)
}

func writePlatformOutput(p []byte) (int, error) {
	if inService, err := svc.IsWindowsService(); err != nil {
		return len(p), err
	} else if inService {
		return len(p), nil
	}
	return os.Stdout.Write(p)
}
