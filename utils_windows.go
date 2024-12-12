package agent

import (
	"io/fs"
	"syscall"
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
