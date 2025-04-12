package utils

import (
	"os"
	"path/filepath"
	"testing"

	"go.viam.com/test"
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

// equivalent to unix touch; creates an empty file at path
func Touch(t *testing.T, path string) {
	f, err := os.Create(path)
	test.That(t, err, test.ShouldBeNil)
	f.Close()
}
