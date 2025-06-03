package utils

import (
	"golang.org/x/sys/unix"
)

func syncfs(fd uintptr) error {
	// Request all file modifications be written to disk
	err := unix.Sync()
	if err != nil {
		return err
	}
	// Request that any modifications to the specific file descriptor be written
	// to disk. According to the unix specification, sync may return early while
	// fsync must block, so cross our fingers that the underlying implementation
	// queues this operation after anything scheduled by sync and we get a
	// consistent state across the target filesystem once it returns.
	return unix.Fsync(int(fd))
}
