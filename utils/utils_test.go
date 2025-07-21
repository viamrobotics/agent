package utils

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.viam.com/rdk/logging"
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

func TestDownloadFile(t *testing.T) {
	MockViamDirs(t)
	logger := logging.NewTestLogger(t)

	t.Run("file:// URL happy path", func(t *testing.T) {
		// Create a test file to download
		testContent := "test file content"
		testFile := filepath.Join(t.TempDir(), "testfile.txt")
		err := os.WriteFile(testFile, []byte(testContent), 0o644)
		test.That(t, err, test.ShouldBeNil)

		// Download the file
		fileURL := "file://" + testFile
		downloadedPath, err := DownloadFile(context.Background(), fileURL, logger)
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
		downloadedPath, err := DownloadFile(context.Background(), server.URL, logger)
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
		existingPath := filepath.Join(ViamDirs["cache"], "duplicate.txt")
		err = os.WriteFile(existingPath, []byte("existing content"), 0o644)
		test.That(t, err, test.ShouldBeNil)

		// Download the file - should create a new file with suffix
		fileURL := "file://" + testFile
		downloadedPath, err := DownloadFile(context.Background(), fileURL, logger)
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
			existingPath := filepath.Join(ViamDirs["cache"], "multidupe.txt"+suffix)
			err = os.WriteFile(existingPath, []byte(fmt.Sprintf("existing content %d", i)), 0o644)
			test.That(t, err, test.ShouldBeNil)
		}

		// Download the file - should create file with .duplicate-003 suffix
		fileURL := "file://" + testFile
		downloadedPath, err := DownloadFile(context.Background(), fileURL, logger)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, strings.HasSuffix(downloadedPath, ".duplicate-003"), test.ShouldBeTrue)

		// Verify new file has correct content
		content, err := os.ReadFile(downloadedPath)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, string(content), test.ShouldEqual, testContent)
	})

	t.Run("returns error for invalid URL", func(t *testing.T) {
		_, err := DownloadFile(context.Background(), "invalid://url", logger)
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "unsupported url scheme")
	})

	t.Run("returns error for non-existent file:// URL", func(t *testing.T) {
		_, err := DownloadFile(context.Background(), "file:///nonexistent/file.txt", logger)
		test.That(t, err, test.ShouldNotBeNil)
	})

	t.Run("returns error for HTTP 404", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		_, err := DownloadFile(context.Background(), server.URL, logger)
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "got response '404 Not Found'")
	})

	t.Run("returns error for HTTP 500", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		_, err := DownloadFile(context.Background(), server.URL, logger)
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "got response '500 Internal Server Error'")
	})

	t.Run("handles context cancellation", func(t *testing.T) {
		// Create a slow server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			w.Write([]byte("content"))
		}))
		defer server.Close()

		// Create a context that cancels immediately
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := DownloadFile(ctx, server.URL, logger)
		test.That(t, err, test.ShouldNotBeNil)
	})

	t.Run("handles network errors", func(t *testing.T) {
		// Try to download from a non-existent server
		_, err := DownloadFile(context.Background(), "https://nonexistent.example.com/file.txt", logger)
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

		_, err := DownloadFile(context.Background(), server.URL, logger)
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
		downloadedPath, err := DownloadFile(context.Background(), fileURL, logger)
		test.That(t, err, test.ShouldBeNil)

		// Verify the content
		content, err := os.ReadFile(downloadedPath)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, string(content), test.ShouldEqual, testContent)
	})
}
