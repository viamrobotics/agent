package utils

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

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
func KillTree(ctx context.Context, pid int) error {
	//nolint:gosec
	cmd := exec.CommandContext(ctx, "taskkill", "/F", "/T", "/PID", strconv.Itoa(pid))
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

// FindProcessesByName returns PIDs of all running processes with the given name (exact match).
func FindProcessesByName(ctx context.Context, name string) ([]int, error) {
	//nolint:gosec
	out, err := exec.CommandContext(ctx, "tasklist", "/FI", "IMAGENAME eq "+name+".exe", "/FO", "CSV", "/NH").Output()
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
		// CSV format: "name.exe","1234","Console","1","10,000 K"
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

// FindChildProcesses returns the direct child processes of parentPID using the Windows API.
func FindChildProcesses(_ context.Context, parentPID int) ([]Process, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(snapshot) //nolint:errcheck

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snapshot, &entry); err != nil {
		return nil, err
	}

	var children []Process
	for {
		if int(entry.ParentProcessID) == parentPID {
			children = append(children, Process{
				PID:  int(entry.ProcessID),
				Name: windows.UTF16ToString(entry.ExeFile[:]),
			})
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}
	return children, nil
}

// stillActive is the value returned by GetExitCodeProcess for a still-running process (STILL_ACTIVE / STATUS_PENDING).
const stillActive = 259

// IsProcessAlive returns true if the process with the given PID is still running.
func IsProcessAlive(pid int) bool {
	//nolint:gosec
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer func() {
		if err := windows.CloseHandle(h); err != nil {
			fmt.Fprintf(os.Stderr, "utils: error closing process handle for pid %d: %v\n", pid, err)
		}
	}()
	var exitCode uint32
	if err := windows.GetExitCodeProcess(h, &exitCode); err != nil {
		return false
	}
	return exitCode == stillActive
}

func SignalForTermination(pid int) error {
	return windows.GenerateConsoleCtrlEvent(syscall.CTRL_BREAK_EVENT, uint32(pid)) //nolint:gosec
}

func writePlatformOutput(p []byte) (int, error) {
	if inService, err := svc.IsWindowsService(); err != nil {
		return len(p), err
	} else if inService {
		return len(p), nil
	}
	return os.Stdout.Write(p)
}
