package utils

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	errw "github.com/pkg/errors"
	"go.viam.com/rdk/logging"
)

func PlatformProcSettings(cmd *exec.Cmd) {}

func KillIfAvailable(logger logging.Logger, cmd *exec.Cmd) {}

// SyncFS implements file system sync for Darwin (macOS).
func SyncFS(syncPath string) (errRet error) {
	file, errRet := os.Open(filepath.Dir(syncPath))
	if errRet != nil {
		return errw.Wrapf(errRet, "syncing fs %s", syncPath)
	}
	defer func() {
		err := file.Close()
		if err != nil {
			errRet = errw.Wrapf(err, "closing file during sync fs %s", syncPath)
		}
	}()

	// On Darwin, we use fsync instead of syncfs
	err := syscall.Fsync(int(file.Fd()))
	if err != nil {
		errRet = errw.Wrapf(err, "syncing fs %s", syncPath)
	}
	return errRet
}

func checkPathOwner(uid int, info fs.FileInfo) error {
	return nil
}

// KillTree kills the process tree.
func KillTree(pid int) error { return nil }
