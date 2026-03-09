package viamserver

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"
)

// findExistingViamServerPIDs returns PIDs of any currently running viam-server.exe processes.
func findExistingViamServerPIDs(ctx context.Context) ([]int, error) {
	out, err := exec.CommandContext(ctx, "tasklist", "/FI", "IMAGENAME eq "+SubsysName+".exe", "/FO", "CSV", "/NH").Output()
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		// tasklist outputs "INFO: No tasks..." when no processes match.
		if line == "" || strings.HasPrefix(line, "INFO") {
			continue
		}
		// CSV format: "viam-server.exe","1234","Console","1","10,000 K"
		parts := strings.SplitN(line, ",", 3)
		if len(parts) < 2 {
			continue
		}
		pidStr := strings.Trim(parts[1], `"`)
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

// stillActive is the value returned by GetExitCodeProcess for a still-running process (STILL_ACTIVE / STATUS_PENDING).
const stillActive = 259

// findChildProcesses returns the direct child processes of parentPID using WMIC.
// Note: WMIC is deprecated in Windows 11 22H2+ but remains available and is the most concise option here.
func findChildProcesses(ctx context.Context, parentPID int) ([]OrphanedProcess, error) {
	//nolint:gosec
	out, err := exec.CommandContext(ctx, "wmic", "process", "where",
		fmt.Sprintf("ParentProcessId=%d", parentPID),
		"get", "ProcessId,Name", "/format:csv").Output()
	if err != nil {
		return nil, err
	}
	var children []OrphanedProcess
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		// CSV format: Node,Name,ProcessId — skip empty lines and the header.
		if line == "" || strings.HasPrefix(line, "Node") {
			continue
		}
		parts := strings.SplitN(line, ",", 3)
		if len(parts) != 3 {
			continue
		}
		name := strings.TrimSpace(parts[1])
		pidStr := strings.TrimSpace(parts[2])
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}
		children = append(children, OrphanedProcess{PID: pid, Name: name})
	}
	return children, nil
}

// IsProcessAlive returns true if the process with the given PID is still running.
func IsProcessAlive(pid int) bool {
	//nolint:gosec
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer func() {
		if err := windows.CloseHandle(h); err != nil {
			fmt.Fprintf(os.Stderr, "viamserver: error closing process handle for pid %d: %v\n", pid, err)
		}
	}()
	var exitCode uint32
	if err := windows.GetExitCodeProcess(h, &exitCode); err != nil {
		return false
	}
	return exitCode == stillActive
}
