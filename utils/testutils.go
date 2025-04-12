package utils

import (
	"os"
	"path/filepath"
	"testing"
)

// replace utils.ViamDirs with t.TempDir for duration of test.
func MockViamDirs(t *testing.T) {
	t.Helper()
	old := ViamDirs
	t.Cleanup(func() {
		ViamDirs = old
	})
	td := t.TempDir()
	ViamDirs = map[string]string{
		"viam": td,
	}
	for _, subdir := range []string{"bin", "cache", "tmp", "etc"} {
		ViamDirs[subdir] = filepath.Join(td, subdir)
		os.Mkdir(ViamDirs[subdir], 0o755)
	}
}
