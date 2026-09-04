package utils

import (
	"os"
	"path/filepath"

	"go.viam.com/rdk/logging"
	rutils "go.viam.com/rdk/utils"
	"go.viam.com/rdk/utils/diskusage"
)

// enoughFreeSpace reports whether the disk that holds path has at least minBytes free.
// It is a package var so that tests can force a low-space result.
var enoughFreeSpace = diskusage.EnoughFreeSpace

// warnIfLowDiskSpace logs a warning if the disk that holds path has less than required bytes
// free. It returns no error, and the caller always continues. The warning is the only signal
// that space is low. If the disk check itself fails, this function logs that instead.
//
// path may name a file that does not exist yet; see nearestExistingDir.
func warnIfLowDiskSpace(logger logging.Logger, path, desc string, required uint64, extraFields ...any) {
	enough, available, err := enoughFreeSpace(nearestExistingDir(path), required)
	if err != nil {
		logger.Warnw("could not check free disk space; proceeding",
			append([]any{"desc", desc, "path", path, "error", err}, extraFields...)...)
		return
	}
	if enough {
		return
	}
	logger.Warnw("not enough free disk space",
		append([]any{
			"desc", desc, "path", path,
			"available", rutils.FormatBytes(available),
			"required", rutils.FormatBytes(required),
		}, extraFields...)...)
}

// nearestExistingDir walks up from path and returns the closest directory that exists. The disk
// check reads the whole disk, so any directory on it gives the same answer, and the closest one
// is right even when a subdirectory is its own mount point.
//
// We resolve this ourselves rather than let diskusage.Usage do it. Usage stops at the first path
// that exists without checking that it is a directory, so it hands back the file itself once a
// partial download is on disk. Windows then fails the check: GetDiskFreeSpaceExW needs a
// directory and reports "The directory name is invalid".
func nearestExistingDir(path string) string {
	for {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			return path
		}
		parent := filepath.Dir(path)
		if parent == path {
			return path
		}
		path = parent
	}
}
