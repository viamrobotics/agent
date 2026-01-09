package utils

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
		Viam:     viam,
		Bin:      filepath.Join(viam, "bin"),
		Cache:    filepath.Join(viam, "cache"),
		Partials: filepath.Join(viam, "cache", "part"),
		Tmp:      filepath.Join(viam, "tmp"),
		Etc:      filepath.Join(viam, "etc"),
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

// ResolveFile returns the path of the given file relative to the root of the codebase.
// For example, if this file currently lives in utils/file.go and ./foo/bar/baz is given,
// then the result is foo/bar/baz. This is helpful when you don't want to relatively refer
// to files when you're not sure where the caller actually lives in relation to the target
// file.
//
// Copied from rdk's utils/file.go.
func ResolveFile(fn string) string {
	//nolint:dogsled
	_, thisFilePath, _, _ := runtime.Caller(0)
	thisDirPath, err := filepath.Abs(filepath.Dir(thisFilePath))
	if err != nil {
		panic(err)
	}
	return filepath.Join(thisDirPath, "..", fn)
}

// BuildViamAgent will attempt to build the viam-agent. If successful, this function will
// return the path to the executable. Leverages the test-build make target.
//
// Mostly copied from rdk's testutils/file_utils.go.
func BuildViamAgent(tb testing.TB) string {
	tb.Helper()

	buildOutputPath := tb.TempDir()
	agentPath := filepath.Join(buildOutputPath, "viam-agent")

	builder := exec.CommandContext(tb.Context(), "make", "test-build")
	// Set Dir to be the root of the repository.
	builder.Dir = ResolveFile(".")
	// Set TESTBUILD_OUTPUT_PATH to be within created temporary directory.
	builder.Env = append(os.Environ(), "TESTBUILD_OUTPUT_PATH="+buildOutputPath)
	out, err := builder.CombinedOutput()
	if len(out) > 0 {
		tb.Logf("Build Output: %s", out)
	}
	if err != nil {
		tb.Error(err)
	}
	if tb.Failed() {
		tb.Fatal("failed to build viam-agent executable")
	}

	return agentPath
}
