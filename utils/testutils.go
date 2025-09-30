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
	ViamDirs = ViamDirsData{
		Viam:  td,
		Bin:   filepath.Join(td, "bin"),
		Cache: filepath.Join(td, "cache"),
		Tmp:   filepath.Join(td, "tmp"),
		Etc:   filepath.Join(td, "etc"),
	}
	for dir := range ViamDirs.Values() {
		err := os.MkdirAll(dir, 0o750)
		test.That(t, err, test.ShouldBeNil)
	}
}

// Touch is equivalent to unix touch; creates an empty file at path.
func Touch(t *testing.T, path string) {
	f, err := os.Create(path) //nolint:gosec
	test.That(t, err, test.ShouldBeNil)
	f.Close() //nolint:gosec,errcheck
}
