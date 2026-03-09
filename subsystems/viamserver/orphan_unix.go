//go:build unix

package viamserver

import (
	"os/exec"
	"strconv"
	"strings"
	"syscall"
)

// findExistingViamServerPIDs returns PIDs of any currently running viam-server processes.
func findExistingViamServerPIDs() ([]int, error) {
	//nolint:gosec
	out, err := exec.Command("pgrep", "-x", SubsysName).Output()
	if err != nil {
		// pgrep exits with code 1 when no processes are found — not an error for us.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil, nil
		}
		return nil, err
	}
	var pids []int
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		pid, err := strconv.Atoi(strings.TrimSpace(line))
		if err != nil {
			continue
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

// IsProcessAlive returns true if the process with the given PID is still running.
func IsProcessAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

// findChildProcesses returns the direct child processes of parentPID.
func findChildProcesses(parentPID int) ([]OrphanedProcess, error) {
	//nolint:gosec
	out, err := exec.Command("pgrep", "-l", "-P", strconv.Itoa(parentPID)).Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil, nil // no children
		}
		return nil, err
	}
	var children []OrphanedProcess
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), " ", 2)
		if len(parts) != 2 {
			continue
		}
		pid, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}
		children = append(children, OrphanedProcess{PID: pid, Name: parts[1]})
	}
	return children, nil
}
