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
	"golang.org/x/sys/windows/svc/eventlog"
)

func PlatformProcSettings(cmd *exec.Cmd) {}

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
	defer syscall.CloseHandle(handle)
	err = syscall.Fsync(handle)
	if err != nil {
		return err
	}
	return nil
}

// KillTree kills the process tree on windows (because other signaling doesn't work).
func KillTree(pid int) error {
	elog, _ := eventlog.Open("viam-agent")
	// note: we're ignoring the log error because we want this to work
	if pid == -1 {
		pid = os.Getpid()
	}
	cmd := exec.Command("WMIC.exe", "process", "where", fmt.Sprintf("ParentProcessId=%d", pid), "get", "ProcessId")
	output, err := cmd.Output()
	if err != nil {
		return err
		// elog.Error(1, fmt.Sprintf("error executing %s %s", cmd.Path, cmd.Args))
		// elog.Error(1, fmt.Sprintf("error getting child process for #%d, #%s", pid, err))
	}
	lines := strings.Split(string(output), "\r\n")
	if elog != nil {
		elog.Info(1, fmt.Sprintf("KillTree stopping %d children of pid %d", len(lines), pid))
	}
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		var childPID int
		_, err := fmt.Sscan(line, &childPID)
		if err != nil {
			if elog != nil {
				elog.Error(1, fmt.Sprintf("not a valid childProcess line %q, #%s", line, err))
			}
			continue
		}
		cmd = exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(childPID))
		err = cmd.Run()
		if elog != nil {
			if err != nil {
				elog.Error(1, fmt.Sprintf("error running taskkill pid %d: #%s", childPID, err))
			} else {
				elog.Info(1, fmt.Sprintf("killed pid %d", childPID))
			}
		}
	}
	if elog != nil {
		elog.Info(1, "KillTree finished")
	}
	return nil
}
