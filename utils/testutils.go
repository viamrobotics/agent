package utils

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
		Viam: td,
	}
	for _, subdir := range []string{"Bin", "Cache", "Tmp", "Etc"} {
		refViamDirs := reflect.ValueOf(&ViamDirs)
		field := refViamDirs.Elem().FieldByName(subdir)
		val := filepath.Join(td, strings.ToLower(subdir))
		field.Set(reflect.ValueOf(val))
		err := os.Mkdir(field.Interface().(string), 0o750)
		test.That(t, err, test.ShouldBeNil)
	}
}

// Touch is equivalent to unix touch; creates an empty file at path.
func Touch(t *testing.T, path string) {
	f, err := os.Create(path) //nolint:gosec
	test.That(t, err, test.ShouldBeNil)
	f.Close() //nolint:gosec,errcheck
}
