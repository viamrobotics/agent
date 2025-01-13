package utils

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"go.viam.com/rdk/logging"
)

// PlatformSubprocessSettings sets platform-specific subprocess settings.
func PlatformSubprocessSettings(cmd *exec.Cmd) {}

// PlatformKill does SIGKILL if available for the platform.
func PlatformKill(logger logging.Logger, cmd *exec.Cmd) {}

func WaitOnline(logger logging.Logger, ctx context.Context) {
	logger.Warn("WaitOnline not available on windows yet")
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
