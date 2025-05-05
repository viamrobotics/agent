package utils

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"go.viam.com/rdk/logging"
	goutils "go.viam.com/utils"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
)

func PlatformProcSettings(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
}

func KillIfAvailable(logger logging.Logger, cmd *exec.Cmd) {}

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

func SendInterrupt(pid int) error {
	return windows.GenerateConsoleCtrlEvent(syscall.CTRL_BREAK_EVENT, uint32(pid)) //nolint:gosec
}

// KillTree kills the process tree on windows (because other signaling doesn't work).
func KillTree(pid int) error {
	elog, err := eventlog.Open("viam-agent")
	if err != nil {
		// Check error but continue since we want this to work
		elog = nil
	}

	if pid == -1 {
		pid = os.Getpid()
	}

	// Use a fixed command string to prevent injection
	//nolint:gosec // WMIC.exe is a fixed command
	cmd := exec.Command("WMIC.exe", "process", "where", fmt.Sprintf("ParentProcessId=%d", pid), "get", "ProcessId")
	output, err := cmd.Output()
	if err != nil {
		return err
	}
	lines := strings.Split(string(output), "\r\n")
	if elog != nil {
		goutils.UncheckedError(elog.Info(1, fmt.Sprintf("KillTree stopping %d children of pid %d", len(lines), pid)))
	}
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		var childPID int
		_, err := fmt.Sscan(line, &childPID)
		if err != nil {
			if elog != nil {
				goutils.UncheckedError(elog.Error(1, fmt.Sprintf("not a valid childProcess line %q, #%s", line, err)))
			}
			continue
		}

		//nolint:gosec // taskkill is a fixed command
		cmd = exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(childPID))
		err = cmd.Run()
		if elog != nil {
			if err != nil {
				goutils.UncheckedError(elog.Error(1, fmt.Sprintf("error running taskkill pid %d: #%s", childPID, err)))
			} else {
				goutils.UncheckedError(elog.Info(1, fmt.Sprintf("killed pid %d", childPID)))
			}
		}
	}
	if elog != nil {
		goutils.UncheckedError(elog.Info(1, "KillTree finished"))
	}
	return nil
}

func writePlatformOutput(p []byte) (int, error) {
	if inService, err := svc.IsWindowsService(); err != nil {
		return len(p), err
	} else if inService {
		return len(p), nil
	}
	return os.Stdout.Write(p)
}
