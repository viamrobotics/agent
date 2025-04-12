package utils

import (
	"os/exec"
	"path/filepath"
	"testing"

	"go.viam.com/test"
)

func TestDecompressFile(t *testing.T) {
	MockViamDirs(t)
	td := t.TempDir()
	if _, err := exec.LookPath("xz"); err != nil {
		t.Skip("no xz command")
	}
	orig := filepath.Join(td, "plaintext")

	// compress an empty file
	Touch(t, orig)
	_, err := exec.Command("xz", orig).Output()
	test.That(t, err, test.ShouldBeNil)

	// decompress
	path, err := DecompressFile(orig + ".xz")
	test.That(t, err, test.ShouldBeNil)
	test.That(t, path, test.ShouldResemble, filepath.Join(ViamDirs["cache"], "plaintext"))
}

func TestGetFileSum(t *testing.T) {
	td := t.TempDir()
	path := filepath.Join(td, "checkme")

	Touch(t, path)

	_, err := GetFileSum(path)
	test.That(t, err, test.ShouldBeNil)
}

func TestCheckIfSame(t *testing.T) {
	td := t.TempDir()

	path1 := filepath.Join(td, "path1")
	path2 := filepath.Join(td, "path2")
	Touch(t, path1)
	Touch(t, path2)

	link := filepath.Join(td, "link")
	test.That(t, ForceSymlink(path1, link), test.ShouldBeNil)

	check := func(path1, path2 string, expected bool) {
		same, err := CheckIfSame(path1, path2)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, same == expected, test.ShouldBeTrue)
	}

	check(path1, path1, true)
	check(path1, path2, false)
	check(link, link, true)
	check(link, path1, true)
	check(link, path2, false)
}

func TestForceSymlink(t *testing.T) {
	td := t.TempDir()
	path := filepath.Join(td, "link")
	target := filepath.Join(td, "target")

	// test initial case
	err := ForceSymlink(target, path)
	test.That(t, err, test.ShouldBeNil)

	// test already-exists case
	err = ForceSymlink(target, path)
	test.That(t, err, test.ShouldBeNil)
}

func TestWriteFileIfNew(t *testing.T) {
	contents := []byte("hello")
	path := filepath.Join(t.TempDir(), "writeme")

	// write new
	written, err := WriteFileIfNew(path, contents)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, written, test.ShouldBeTrue)

	// unchanged
	written, err = WriteFileIfNew(path, contents)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, written, test.ShouldBeFalse)

	// changed
	written, err = WriteFileIfNew(path, []byte("other contents"))
	test.That(t, err, test.ShouldBeNil)
	test.That(t, written, test.ShouldBeTrue)
}
