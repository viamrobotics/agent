package utils

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"go.viam.com/rdk/logging"
	"go.viam.com/test"
)

// TestDownloadFileURLForms documents which URL spellings DownloadFile accepts for a local
// file. file:// URLs are a supported way to pin a custom binary (see examples/agent-config.jsonc),
// and on Windows the drive letter makes the spelling ambiguous: url.Parse variously drops the
// drive into the URL host or leaves a leading slash before it, so DownloadFile normalizes via
// go-getter's URL helper. This table is the canonical list of forms we intend to support -- if
// you change URL parsing in DownloadFile, the pass/fail here tells you exactly which spellings
// still resolve to the local file.
func TestDownloadFileURLForms(t *testing.T) {
	MockAndCreateViamDirs(t)
	logger := logging.NewTestLogger(t)

	const content = "canonical source binary contents"
	// EvalSymlinks so the path matches what the getter resolves (e.g. /var -> /private/var on darwin).
	td, err := filepath.EvalSymlinks(t.TempDir())
	test.That(t, err, test.ShouldBeNil)
	src := filepath.Join(td, "source.bin")
	test.That(t, os.WriteFile(src, []byte(content), 0o644), test.ShouldBeNil)

	// forward-slash spelling of the source path; on Windows "C:\x" -> "C:/x", on unix unchanged.
	fwd := filepath.ToSlash(src)

	type urlCase struct {
		name    string
		url     string
		wantErr bool
	}

	var cases []urlCase
	if runtime.GOOS == "windows" {
		cases = []urlCase{
			// Native Windows path after the scheme: file://C:\Users\...\source.bin
			{"two-slash, backslashes", "file://" + src, false},
			// Forward slashes; the drive letter parses into the URL host and we move it back.
			{"two-slash, forward slashes", "file://" + fwd, false},
			// Standards-correct Windows file URI: three slashes, then the drive letter.
			{"three-slash, drive letter", "file:///" + fwd, false},
		}
	} else {
		cases = []urlCase{
			// Canonical POSIX file URI: the leading "/" of the absolute path makes three slashes.
			{"absolute path", "file://" + src, false},
		}
	}
	// A path that does not exist must surface an error regardless of platform or spelling.
	cases = append(cases, urlCase{"nonexistent file", "file://" + filepath.ToSlash(filepath.Join(td, "missing.bin")), true})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("url = %q", tc.url)
			downloadedPath, err := DownloadFile(t.Context(), tc.url, logger)
			if tc.wantErr {
				test.That(t, err, test.ShouldNotBeNil)
				return
			}
			test.That(t, err, test.ShouldBeNil)
			got, err := os.ReadFile(downloadedPath)
			test.That(t, err, test.ShouldBeNil)
			test.That(t, string(got), test.ShouldEqual, content)
		})
	}
}
