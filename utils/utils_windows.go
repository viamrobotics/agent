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
)

func PlatformProcSettings(cmd *exec.Cmd) {}

func PlatformKill(logger logging.Logger, cmd *exec.Cmd) {}

// platform-specific UID check.
func checkPathOwner(uid int, info fs.FileInfo) error {
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
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		var childPID int
		_, err := fmt.Sscan(line, &childPID)
		if err != nil {
			// elog.Error(1, fmt.Sprintf("not a valid childProcess line %s, #%s", line, err))
			continue
		}
		cmd = exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(childPID))
		cmd.Run()
		// err = cmd.Run()
		// if err != nil {
		// 	// elog.Error(1, fmt.Sprintf("error running taskkill #%s", err))
		// }
	}
	return nil
}
