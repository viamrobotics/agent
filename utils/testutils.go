package utils

import (
	"os"
	"path/filepath"
	"testing"

	"go.viam.com/test"
)

// MockAndCreateViamDirs calls [MockViamDirs], then creates all those
// directories. It returns the temporary directory that is the parent of the
// viam directory.
func MockAndCreateViamDirs(t *testing.T) string {
	t.Helper()
	td := MockViamDirs(t)
	for dir := range ViamDirs.Values() {
		//nolint: gosec
		err := os.MkdirAll(dir, 0o755)
		test.That(t, err, test.ShouldBeNil)
	}
	return td
}

// MockViamDirs replaces utils.ViamDirs members with paths in
// t.TempDir for duration of test. It returns the temporary directory that is
// the parent of the viam directory.
func MockViamDirs(t *testing.T) string {
	t.Helper()
	old := ViamDirs
	t.Cleanup(func() {
		ViamDirs = old
	})
	td := t.TempDir()
	viam := filepath.Join(td, "viam")
	ViamDirs = ViamDirsData{
		Viam:  viam,
		Bin:   filepath.Join(viam, "bin"),
		Cache: filepath.Join(viam, "cache"),
		Tmp:   filepath.Join(viam, "tmp"),
		Etc:   filepath.Join(viam, "etc"),
	}
	return td
}

func MockBuildInfo(t *testing.T, version, revision string) {
	originalVersion := Version
	originalRevision := GitRevision
	t.Cleanup(func() {
		Version = originalVersion
		GitRevision = originalRevision
	})
	Version = version
	GitRevision = revision
}

// Touch is equivalent to unix touch; creates an empty file at path.
func Touch(t *testing.T, path string) {
	f, err := os.Create(path) //nolint:gosec
	test.That(t, err, test.ShouldBeNil)
	f.Close() //nolint:gosec,errcheck
}
