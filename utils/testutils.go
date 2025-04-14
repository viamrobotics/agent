package utils

import (
	"os"
	"path/filepath"
	"testing"

	"go.viam.com/test"
)

// MockViamDirs replaces utils.ViamDirs entries with t.TempDir for duration of test.
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
		err := os.Mkdir(ViamDirs[subdir], 0o750)
		test.That(t, err, test.ShouldBeNil)
	}
}

// Touch is equivalent to unix touch; creates an empty file at path.
func Touch(t *testing.T, path string) {
	f, err := os.Create(path) //nolint:gosec
	test.That(t, err, test.ShouldBeNil)
	f.Close() //nolint:gosec,errcheck
}
