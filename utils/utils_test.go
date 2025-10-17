package utils

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"go.viam.com/rdk/logging"
	"go.viam.com/test"
)

func TestDecompressFile(t *testing.T) {
	MockAndCreateViamDirs(t)
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
	test.That(t, path, test.ShouldResemble, filepath.Join(ViamDirs.Cache, "plaintext"))
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

func TestDownloadFile(t *testing.T) {
	MockAndCreateViamDirs(t)
	logger := logging.NewTestLogger(t)

	t.Run("file:// URL happy path", func(t *testing.T) {
		// Create a test file to download
		testContent := "test file content"
		testFile := filepath.Join(t.TempDir(), "testfile.txt")
		err := os.WriteFile(testFile, []byte(testContent), 0o644)
		test.That(t, err, test.ShouldBeNil)

		// Download the file
		fileURL := "file://" + testFile
		downloadedPath, err := DownloadFile(t.Context(), fileURL, logger)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, downloadedPath, test.ShouldNotBeEmpty)

		// Verify the content
		content, err := os.ReadFile(downloadedPath)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, string(content), test.ShouldEqual, testContent)
	})

	t.Run("https:// URL happy path", func(t *testing.T) {
		// Create a test server
		testContent := "https test content"
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(testContent))
		}))
		defer server.Close()

		// Download the file
		downloadedPath, err := DownloadFile(t.Context(), server.URL, logger)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, downloadedPath, test.ShouldNotBeEmpty)

		// Verify the content
		content, err := os.ReadFile(downloadedPath)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, string(content), test.ShouldEqual, testContent)
	})

	t.Run("does not overwrite existing files", func(t *testing.T) {
		// Create a test file to download
		testContent := "original content"
		testFile := filepath.Join(t.TempDir(), "duplicate.txt")
		err := os.WriteFile(testFile, []byte(testContent), 0o644)
		test.That(t, err, test.ShouldBeNil)

		// Create an existing file in cache with same name
		existingPath := filepath.Join(ViamDirs.Cache, "duplicate.txt")
		err = os.WriteFile(existingPath, []byte("existing content"), 0o644)
		test.That(t, err, test.ShouldBeNil)

		// Download the file - should create a new file with suffix
		fileURL := "file://" + testFile
		downloadedPath, err := DownloadFile(t.Context(), fileURL, logger)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, downloadedPath, test.ShouldNotEqual, existingPath)
		test.That(t, strings.HasSuffix(downloadedPath, ".duplicate-001"), test.ShouldBeTrue)

		// Verify original file is unchanged
		content, err := os.ReadFile(existingPath)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, string(content), test.ShouldEqual, "existing content")

		// Verify new file has correct content
		content, err = os.ReadFile(downloadedPath)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, string(content), test.ShouldEqual, testContent)
	})

	t.Run("handles multiple duplicates", func(t *testing.T) {
		// Create a test file to download
		testContent := "test content"
		testFile := filepath.Join(t.TempDir(), "multidupe.txt")
		err := os.WriteFile(testFile, []byte(testContent), 0o644)
		test.That(t, err, test.ShouldBeNil)

		// Create multiple existing files
		for i := range 3 {
			var suffix string
			if i > 0 {
				suffix = fmt.Sprintf(".duplicate-%03d", i)
			}
			existingPath := filepath.Join(ViamDirs.Cache, "multidupe.txt"+suffix)
			err = os.WriteFile(existingPath, []byte(fmt.Sprintf("existing content %d", i)), 0o644)
			test.That(t, err, test.ShouldBeNil)
		}

		// Download the file - should create file with .duplicate-003 suffix
		fileURL := "file://" + testFile
		downloadedPath, err := DownloadFile(t.Context(), fileURL, logger)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, strings.HasSuffix(downloadedPath, ".duplicate-003"), test.ShouldBeTrue)

		// Verify new file has correct content
		content, err := os.ReadFile(downloadedPath)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, string(content), test.ShouldEqual, testContent)
	})

	t.Run("returns error for invalid URL", func(t *testing.T) {
		_, err := DownloadFile(t.Context(), "invalid://url", logger)
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "unsupported url scheme")
	})

	t.Run("returns error for non-existent file:// URL", func(t *testing.T) {
		_, err := DownloadFile(t.Context(), "file:///nonexistent/file.txt", logger)
		test.That(t, err, test.ShouldNotBeNil)
	})

	t.Run("returns error for HTTP 404", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		_, err := DownloadFile(t.Context(), server.URL, logger)
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "bad response code: 404")
	})

	t.Run("returns error for HTTP 500", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		_, err := DownloadFile(t.Context(), server.URL, logger)
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "bad response code: 500")
	})

	t.Run("handles context cancellation", func(t *testing.T) {
		// Create a slow server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			w.Write([]byte("content"))
		}))
		defer server.Close()

		// Create a context that cancels immediately
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		_, err := DownloadFile(ctx, server.URL, logger)
		test.That(t, err, test.ShouldNotBeNil)
	})

	t.Run("handles network errors", func(t *testing.T) {
		// Try to download from a non-existent server
		_, err := DownloadFile(t.Context(), "https://nonexistent.example.com/file.txt", logger)
		test.That(t, err, test.ShouldNotBeNil)
	})

	t.Run("handles incomplete downloads", func(t *testing.T) {
		// Create a server that closes connection early
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("partial content"))
			// Close the connection abruptly
			if h, ok := w.(http.Hijacker); ok {
				if conn, _, err := h.Hijack(); err == nil {
					conn.Close()
				}
			}
		}))
		defer server.Close()

		_, err := DownloadFile(t.Context(), server.URL, logger)
		test.That(t, err, test.ShouldNotBeNil)
	})

	t.Run("handles files with special characters in name", func(t *testing.T) {
		// Create a test file with special characters
		testContent := "special chars content"
		testFile := filepath.Join(t.TempDir(), "file with spaces & symbols.txt")
		err := os.WriteFile(testFile, []byte(testContent), 0o644)
		test.That(t, err, test.ShouldBeNil)

		// Download the file
		fileURL := "file://" + testFile
		downloadedPath, err := DownloadFile(t.Context(), fileURL, logger)
		test.That(t, err, test.ShouldBeNil)

		// Verify the content
		content, err := os.ReadFile(downloadedPath)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, string(content), test.ShouldEqual, testContent)
	})
}

// If either of the tests on ViamDirsData become outdated be sure there is at
// least some test remaining on the ViamDirsData.Values method. As long as it
// uses reflection it could break at runtime if we accidentally add a
// non-string field and we want to be sure to catch that in testing.
func TestViamDirsValuesCopy(t *testing.T) {
	// Test that the iterator takes a copy at the time it is created and does not
	// reflect changes made to the original value after that point.
	backup := ViamDirs
	t.Cleanup(func() {
		ViamDirs = backup
	})

	ViamDirs.Bin = "TEST-foo"
	seq := ViamDirs.Values()
	ViamDirs.Cache = "TEST-bar"

	testVals := []string{}
	for val := range seq {
		if !strings.HasPrefix(val, "TEST-") {
			continue
		}
		val := strings.Split(val, "-")[1]
		testVals = append(testVals, val)
	}
	test.That(t, testVals, test.ShouldResemble, []string{"foo"})
}

func TestViamDirsValuesEmpty(t *testing.T) {
	// Test that the iterator does not include empty strings.
	backup := ViamDirs
	t.Cleanup(func() {
		ViamDirs = backup
	})

	initialLen := len(slices.Collect(ViamDirs.Values()))
	test.That(t, initialLen, test.ShouldBeGreaterThan, 2)

	ViamDirs.Bin = ""
	ViamDirs.Tmp = ""
	newLen := len(slices.Collect(ViamDirs.Values()))
	test.That(t, newLen, test.ShouldEqual, initialLen-2)
}

func TestInitPaths(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		MockViamDirs(t)
		err := InitPaths()
		test.That(t, err, test.ShouldBeNil)
	})

	t.Run("failure cannot create directory", func(t *testing.T) {
		td := MockViamDirs(t)
		err := os.Chmod(td, 0o500)
		test.That(t, err, test.ShouldBeNil)
		err = InitPaths()
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "creating directory")
	})

	t.Run("failure not directory", func(t *testing.T) {
		MockViamDirs(t)
		err := os.MkdirAll(ViamDirs.Viam, os.ModePerm)
		test.That(t, err, test.ShouldBeNil)
		_, err = os.Create(ViamDirs.Bin)
		test.That(t, err, test.ShouldBeNil)
		err = InitPaths()
		test.That(t, err, test.ShouldBeError, ViamDirs.Bin+" should be a directory, but is not")
	})

	t.Run("failure wrong mode", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			// Windows doesn't have Unix style file modes
			t.SkipNow()
		}
		MockViamDirs(t)
		err := os.MkdirAll(ViamDirs.Bin, os.ModePerm)
		test.That(t, err, test.ShouldBeNil)
		os.Chmod(ViamDirs.Bin, 0o700)
		err = InitPaths()
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, ViamDirs.Bin+" should have permission set to")
	})
}

func TestPartialPath(t *testing.T) {
	path := CreatePartialPath("https://storage.googleapis.com/packages.viam.com/apps/viam-server/viam-server-latest-x86_64")
	maxPathLengths := map[string]int{
		"linux":   4096,
		"windows": 260,
	}
	for _, maxPath := range maxPathLengths {
		test.That(t, len(path), test.ShouldBeLessThanOrEqualTo, maxPath)
	}
}

func TestRewriteGCPDownload(t *testing.T) {
	u1, _ := url.Parse("https://google.com")
	u2, _ := url.Parse("https://storage.googleapis.com/packages.viam.com/apps/viam-server/viam-server-v0.96.0-aarch64?generation=1759865152533030&alt=media")                             //nolint:lll
	u3, _ := url.Parse("https://storage.googleapis.com/download/storage/v1/b/packages.viam.com/o/apps%2Fviam-server%2Fviam-server-v0.96.0-aarch64?generation=1759865152533030&alt=media") //nolint:lll

	// normal URLs should not be rewritten
	rewrite1, b1 := rewriteGCPDownload(u1)
	rewrite2, b2 := rewriteGCPDownload(u2)
	test.That(t, rewrite1, test.ShouldResemble, u1)
	test.That(t, b1, test.ShouldBeFalse)
	test.That(t, rewrite2, test.ShouldResemble, u2)
	test.That(t, b2, test.ShouldBeFalse)

	// matching URLs should be rewritten
	rewrite3, b3 := rewriteGCPDownload(u3)
	test.That(t, rewrite3, test.ShouldResemble, u2)
	test.That(t, b3, test.ShouldBeTrue)
	test.That(t, rewrite3.EscapedPath(), test.ShouldResemble, u2.EscapedPath())
}
