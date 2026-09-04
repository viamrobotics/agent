package utils

import (
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
// path must be a directory. The check reads the whole disk, so any directory on it works.
// Callers must not pass a file path: on Windows GetDiskFreeSpaceExW rejects one, and
// diskusage.Usage stops walking up at the first path that exists, which is the file itself
// once a partial download is on disk.
func warnIfLowDiskSpace(logger logging.Logger, path, desc string, required uint64, extraFields ...any) {
	enough, available, err := enoughFreeSpace(path, required)
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
