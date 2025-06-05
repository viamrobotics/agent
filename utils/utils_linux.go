package utils

import (
	"golang.org/x/sys/unix"
)

func syncfs(fd uintptr) error {
	return unix.Syncfs(int(fd))
}
