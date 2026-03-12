//go:build unix

package utils

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	errw "github.com/pkg/errors"
)

func PlatformProcSettings(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

func writePlatformOutput(p []byte) (int, error) {
	return os.Stdout.Write(p)
}

// platform-specific UID check.
func checkPathOwner(uid int, info fs.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		// should be impossible on Linux/macOS
		return errw.New("cannot convert to syscall.Stat_t")
	}
	if uid != int(stat.Uid) {
		return errw.Errorf("%s is owned by UID %d but the current UID is %d", info.Name(), stat.Uid, uid)
	}
	return nil
}

func SignalForTermination(pid int) error {
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		return errw.Wrapf(err, "signaling PID %d", pid)
	}
	return nil
}

// KillTree sends SIGKILL to the process group.
func KillTree(ctx context.Context, pid int) error {
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil {
		return errw.Wrapf(err, "killing PID %d", pid)
	}
	return nil
}

// FindProcessesByName returns PIDs of all running processes with the given name (exact match).
func FindProcessesByName(ctx context.Context, name string) ([]int, error) {
	out, err := exec.CommandContext(ctx, "pgrep", "-x", name).Output()
	if err != nil {
		// pgrep exits with code 1 when no processes are found — not an error for us.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
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

// FindChildProcesses returns the direct child processes of parentPID.
func FindChildProcesses(ctx context.Context, parentPID int) ([]Process, error) {
	//nolint:gosec
	out, err := exec.CommandContext(ctx, "pgrep", "-l", "-P", strconv.Itoa(parentPID)).Output()
	if err != nil {
		// pgrep exits with code 1 when no processes are found — not an error for us.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return nil, nil
		}
		return nil, err
	}
	var children []Process
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), " ", 2)
		if len(parts) != 2 {
			continue
		}
		pid, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}
		children = append(children, Process{PID: pid, Name: parts[1]})
	}
	return children, nil
}

// IsProcessAlive returns true if the process with the given PID is still running.
func IsProcessAlive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

func SyncFS(syncPath string) (errRet error) {
	file, errRet := os.Open(filepath.Dir(syncPath))
	if errRet != nil {
		return errw.Wrapf(errRet, "syncing fs %s", syncPath)
	}
	err := syncfs(file.Fd())
	if err != nil {
		errRet = errw.Wrapf(err, "syncing fs %s", syncPath)
	}
	return errors.Join(errRet, file.Close())
}
