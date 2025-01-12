package agent

import (
	"io/fs"
	"os/exec"
	"syscall"

	errw "github.com/pkg/errors"
)

// platform-specific UID check.
func checkPathOwner(uid int, info fs.FileInfo) error {
	// todo: figure this out on windows.
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

func RequestRestart() error {
	// note: sc.exe doesn't have a restart command it seems.
	// note: this stops but doesn't start
	// if _, err := exec.Command("powershell", "-command", "Restart-Service viam-agent").Output(); err != nil {
	// 	return false, errw.Wrap(err, "restarting windows service")
	// }
	// if agent.GlobalCancel == nil {
	// 	return false, errors.New("can't call globalCancel because it's nil")
	// }
	// agent.GlobalCancel()
	// if inService, err := svc.IsWindowsService(); err != nil {
	// 	return errw.Wrap(err, "can't request restart -- error checking whether in service")
	// } else if !inService {
	// 	return errors.New("can't request restart -- not in service")
	// }
	if _, err := exec.Command("net", "stop", "viam-agent").Output(); err != nil {
		return errw.Wrap(err, "restarting windows service")
	}
	return nil
}
