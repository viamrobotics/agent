package agent

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/viamrobotics/agent/subsystems/viamserver"
	"github.com/viamrobotics/agent/utils"
	pb "go.viam.com/api/app/agent/v1"
	"go.viam.com/rdk/logging"
	"go.viam.com/test"
	goutils "go.viam.com/utils"
)

func TestUpdate(t *testing.T) {
	utils.MockAndCreateViamDirs(t)
	logger := logging.NewTestLogger(t)

	// sha of an empty file
	goodSHA, err := hex.DecodeString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	test.That(t, err, test.ShouldBeNil)

	td := t.TempDir()
	binPath := filepath.Join(td, "fake-binary")
	f, err := os.Create(binPath)
	test.That(t, err, test.ShouldBeNil)
	f.Close()

	vc := NewVersionCache(logger)

	t.Run("corrected-sha-is-picked-up", func(t *testing.T) {
		err := vc.Update(&pb.UpdateInfo{
			Version:  "0.90.0",
			Url:      "file://" + binPath,
			Filename: "viam-server",
			Sha256:   []byte("WRONG_SHA_WRONG_SHA_WRONG_SHA_WW"),
		}, viamserver.SubsysName)
		test.That(t, err, test.ShouldBeNil)

		// the download succeeds but the checksum comparison fails
		_, err = vc.UpdateBinary(t.Context(), viamserver.SubsysName)
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "sha256")

		// the manifest is corrected in place: same version string, fixed sha
		err = vc.Update(&pb.UpdateInfo{
			Version:  "0.90.0",
			Url:      "file://" + binPath,
			Filename: "viam-server",
			Sha256:   goodSHA,
		}, viamserver.SubsysName)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, vc.ViamServer.Versions["0.90.0"].UnpackedSHA, test.ShouldResemble, goodSHA)

		// the already-downloaded binary now matches, so the update completes
		needsRestart, err := vc.UpdateBinary(t.Context(), viamserver.SubsysName)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, needsRestart, test.ShouldBeTrue)
		test.That(t, vc.ViamServer.CurrentVersion, test.ShouldEqual, "0.90.0")
	})

	t.Run("unchanged-update-leaves-brokenTarget", func(t *testing.T) {
		vc.ViamServer.brokenTarget = true
		err := vc.Update(&pb.UpdateInfo{
			Version:  "0.90.0",
			Url:      "file://" + binPath,
			Filename: "viam-server",
			Sha256:   goodSHA,
		}, viamserver.SubsysName)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, vc.ViamServer.brokenTarget, test.ShouldBeTrue)
		vc.ViamServer.brokenTarget = false
	})

	t.Run("customURL-sha-not-overwritten", func(t *testing.T) {
		customURL := "file://" + binPath
		err := vc.Update(&pb.UpdateInfo{
			Version:  "customURL",
			Url:      customURL,
			Filename: "viam-server",
		}, viamserver.SubsysName)
		test.That(t, err, test.ShouldBeNil)

		// simulate UpdateBinary having stored the locally computed sha
		info := vc.ViamServer.Versions["customURL+"+customURL]
		localSHA := []byte("locally-computed-sha-32-bytes-xx")
		info.UnpackedSHA = localSHA

		err = vc.Update(&pb.UpdateInfo{
			Version:  "customURL",
			Url:      customURL,
			Filename: "viam-server",
			Sha256:   []byte("some-serverside-value-32-bytes-x"),
		}, viamserver.SubsysName)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, info.UnpackedSHA, test.ShouldResemble, localSHA)
	})

	t.Run("retarget-customURL-clears-sha", func(t *testing.T) {
		customURL := "file://" + binPath
		info := vc.ViamServer.Versions["customURL+"+customURL]
		info.UnpackedSHA = []byte("locally-computed-sha-32-bytes-xx")

		// switching away and back is the dev workflow for picking up a rebuilt
		// binary at the same URL; it must clear the sha to force a re-fetch
		for _, update := range []*pb.UpdateInfo{
			{Version: "0.90.0", Url: "file://" + binPath, Filename: "viam-server", Sha256: goodSHA},
			{Version: "customURL", Url: customURL, Filename: "viam-server"},
		} {
			test.That(t, vc.Update(update, viamserver.SubsysName), test.ShouldBeNil)
		}
		test.That(t, info.UnpackedSHA, test.ShouldBeNil)
	})
}

func TestUpdateBinary(t *testing.T) {
	utils.MockAndCreateViamDirs(t)
	logger := logging.NewTestLogger(t)

	t.Run("viam-server", func(t *testing.T) {
		vi := VersionInfo{
			Version:     "0.70.0",
			SymlinkPath: filepath.Join(utils.ViamDirs.Bin, "viam-server"),
		}
		// sha of an empty file
		var err error
		vi.UnpackedSHA, err = hex.DecodeString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
		test.That(t, err, test.ShouldBeNil)

		vi2 := vi
		vi2.Version = "0.71.0"

		td := t.TempDir()
		for _, v := range []*VersionInfo{&vi, &vi2} {
			f, err := os.Create(filepath.Join(td, "source-binary-"+v.Version))
			test.That(t, err, test.ShouldBeNil)
			f.Close()
			v.URL = "file://" + f.Name()
		}

		vc := VersionCache{
			logger:             logger,
			cacheCleanupLogger: logger,
			ViamServer: &Versions{
				TargetVersion: vi.Version,
				Versions: map[string]*VersionInfo{
					vi.Version:  &vi,
					vi2.Version: &vi2,
				},
			},
		}

		t.Run("initial-install", func(t *testing.T) {
			needsRestart, err := vc.UpdateBinary(t.Context(), viamserver.SubsysName)
			test.That(t, err, test.ShouldBeNil)
			test.That(t, needsRestart, test.ShouldBeTrue)
			testExists(t, filepath.Join(utils.ViamDirs.Bin, "viam-server"))
			testExists(t, filepath.Join(utils.ViamDirs.Cache, "source-binary-"+vi.Version))
			test.That(t, vi.UnpackedPath, test.ShouldResemble, vi.DlPath)
		})

		t.Run("rerun-with-no-change", func(t *testing.T) {
			needsRestart, err := vc.UpdateBinary(t.Context(), viamserver.SubsysName)
			test.That(t, err, test.ShouldBeNil)
			test.That(t, needsRestart, test.ShouldBeFalse)
		})

		t.Run("upgrade", func(t *testing.T) {
			vc.ViamServer.TargetVersion = vi2.Version
			needsRestart, err := vc.UpdateBinary(t.Context(), viamserver.SubsysName)
			test.That(t, err, test.ShouldBeNil)
			test.That(t, needsRestart, test.ShouldBeTrue)
			testExists(t, filepath.Join(utils.ViamDirs.Cache, "source-binary-"+vi2.Version))
		})

		t.Run("checksum-wrong-at-top-should-redownload", func(t *testing.T) {
			// case where checksum is wrong at the top of UpdateBinary
			// (I think we get here by having a binary not tracked in cache)
			vi3 := vi2
			vi3.Version = "0.71.1"
			vc.ViamServer.Versions[vi3.Version] = &vi3
			vc.ViamServer.TargetVersion = vi3.Version
			_, err = vc.UpdateBinary(t.Context(), viamserver.SubsysName)
			test.That(t, err, test.ShouldBeNil)

			// run again and confirm that the mtime doesn't change
			stat, _ := os.Stat(vi3.UnpackedPath)
			mtime := stat.ModTime()
			needsRestart, err := vc.UpdateBinary(t.Context(), viamserver.SubsysName)
			test.That(t, err, test.ShouldBeNil)
			test.That(t, needsRestart, test.ShouldBeFalse)
			stat, _ = os.Stat(vi3.UnpackedPath)
			test.That(t, stat.ModTime(), test.ShouldEqual, mtime)

			// edit the file, confirm that mtime changes + needsRestart = true
			err = os.WriteFile(vi3.UnpackedPath, []byte("bad contents"), 0o666)
			test.That(t, err, test.ShouldBeNil)
			stat, _ = os.Stat(vi3.UnpackedPath)
			mtime = stat.ModTime()
			time.Sleep(time.Millisecond * 10) // mtime check is flaky otherwise
			needsRestart, err = vc.UpdateBinary(t.Context(), viamserver.SubsysName)
			test.That(t, err, test.ShouldBeNil)
			test.That(t, needsRestart, test.ShouldBeTrue)
			stat, _ = os.Stat(vi3.UnpackedPath)
			test.That(t, stat.ModTime().After(mtime), test.ShouldBeTrue)
		})

		t.Run("checksum-wrong-after-download-should-error", func(t *testing.T) {
			// When the checksum of downloaded file is wrong, confirm that we error.
			vi4 := vi2
			vi4.Version = "0.71.2"
			vi4.UnpackedSHA = []byte("WRONG")
			vc.ViamServer.Versions[vi4.Version] = &vi4
			vc.ViamServer.TargetVersion = vi4.Version
			err := os.Remove(vi4.UnpackedPath)
			test.That(t, err == nil || os.IsNotExist(err), test.ShouldBeTrue)

			needsRestart, err := vc.UpdateBinary(t.Context(), viamserver.SubsysName)
			test.That(t, needsRestart, test.ShouldBeFalse)
			test.That(t, err.Error(), test.ShouldContainSubstring, "sha256")

			// TODO(APP-10012): fix bad-checksum cleanup logic and restore this check.
			// _, err = os.Stat(vi4.UnpackedPath)
			// test.That(t, os.IsNotExist(err), test.ShouldBeTrue)
		})

		t.Run("custom-url", func(t *testing.T) {
			port, err := goutils.TryReserveRandomPort()
			test.That(t, err, test.ShouldBeNil)

			baseURL := fmt.Sprintf(":%d", port)
			baseURLWithScheme := fmt.Sprintf("%s://localhost%s", "http", baseURL)

			var (
				prefixBytes       []byte
				contentTypeHeader string
			)
			switch runtime.GOOS {
			case "linux":
				prefixBytes = []byte{0x7f, 'E', 'L', 'F'}
				contentTypeHeader = "application/x-executable"
			case "darwin":
				prefixBytes = []byte{0xcf, 0xfa, 0xed, 0xfe}
				contentTypeHeader = "application/x-mach-binary"
			}

			mux := http.NewServeMux()
			mux.HandleFunc("/nolm", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", contentTypeHeader)
				w.Write(prefixBytes)
			})
			mux.HandleFunc("/lm", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Last-Modified", "Tue, 09 Dec 2025 18:52:44 GMT")
				w.Write(prefixBytes)
			})
			mux.HandleFunc("/badlm", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Last-Modified", "asdfghjkl")
				w.Write(prefixBytes)
			})
			server := &http.Server{Addr: baseURL, Handler: mux}
			wg := sync.WaitGroup{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := server.ListenAndServe(); err != nil {
					test.That(t, err, test.ShouldEqual, http.ErrServerClosed)
				}
			}()

			ctx := t.Context()
			lmURL, err := url.JoinPath(baseURLWithScheme, "/lm")
			test.That(t, err, test.ShouldBeNil)

			vi5 := vi2
			vi5.LastModified = time.Time{}
			vi5.LastModifiedCheck = time.Time{}
			vi5.Version = fmt.Sprintf("customURL+%s", lmURL)
			vi5.URL = lmURL
			vi5.UnpackedSHA = make([]byte, 0)
			vc.ViamServer.Versions[vi5.Version] = &vi5
			vc.ViamServer.TargetVersion = vi5.Version

			// update from previous to customURL: download and restart needed
			needsRestart, err := vc.UpdateBinary(ctx, viamserver.SubsysName)

			test.That(t, needsRestart, test.ShouldBeTrue)
			test.That(t, err, test.ShouldBeNil)

			vi5.LastModified = time.Time{}
			vi5.LastModifiedCheck = time.Time{}
			// initial 0->populated: no download or restart needed
			needsRestart, err = vc.UpdateBinary(ctx, viamserver.SubsysName)

			test.That(t, err, test.ShouldBeNil)
			test.That(t, needsRestart, test.ShouldBeFalse)
			test.That(t, vi5.LastModified.IsZero(), test.ShouldBeFalse)
			test.That(t, vi5.LastModifiedCheck.IsZero(), test.ShouldBeFalse)

			// test LastModified increased: download & restart needed
			vi5.LastModified = time.Time{}.Add(time.Second)
			vi5.LastModifiedCheck = time.Time{}.Add(time.Second)

			needsRestart, err = vc.UpdateBinary(ctx, viamserver.SubsysName)
			test.That(t, needsRestart, test.ShouldBeTrue)
			test.That(t, err, test.ShouldBeNil)

			// test unparseable Last-Modified: do nothing
			vi5.LastModified = time.Time{}.Add(time.Second)
			vi5.LastModifiedCheck = time.Time{}.Add(time.Second)

			badLmURL, err := url.JoinPath(baseURLWithScheme, "/badlm")
			test.That(t, err, test.ShouldBeNil)
			vi5.URL = badLmURL

			needsRestart, err = vc.UpdateBinary(ctx, viamserver.SubsysName)
			test.That(t, err, test.ShouldBeNil)
			test.That(t, needsRestart, test.ShouldBeFalse)
			test.That(t, vi5.LastModified, test.ShouldEqual, time.Time{}.Add(time.Second))

			// test unpopulated Last-Modified: do nothing
			vi5.LastModified = time.Time{}.Add(time.Second)
			vi5.LastModifiedCheck = time.Time{}.Add(time.Second)

			noLmURL, err := url.JoinPath(baseURLWithScheme, "/nolm")
			test.That(t, err, test.ShouldBeNil)
			vi5.URL = noLmURL

			needsRestart, err = vc.UpdateBinary(ctx, viamserver.SubsysName)
			test.That(t, err, test.ShouldBeNil)
			test.That(t, needsRestart, test.ShouldBeFalse)
			test.That(t, vi5.LastModified, test.ShouldEqual, time.Time{}.Add(time.Second))

			err = server.Shutdown(ctx)
			test.That(t, err, test.ShouldBeNil)
			wg.Wait()
		})
	})

	t.Run("viam-agent", func(t *testing.T) {
		vi := VersionInfo{
			Version:     "0.23.0",
			SymlinkPath: filepath.Join(utils.ViamDirs.Bin, "viam-agent"),
		}
		// Mimic SHA of an empty file.
		var err error
		vi.UnpackedSHA, err = hex.DecodeString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
		test.That(t, err, test.ShouldBeNil)

		vi2 := vi
		vi2.Version = "0.24.0"

		td := t.TempDir()
		for _, v := range []*VersionInfo{&vi, &vi2} {
			f, err := os.Create(filepath.Join(td, "source-binary-"+v.Version))
			test.That(t, err, test.ShouldBeNil)
			f.Close()
			v.URL = "file://" + f.Name()
		}

		vc := VersionCache{
			logger:             logger,
			cacheCleanupLogger: logger,
			ViamAgent: &Versions{
				TargetVersion: vi.Version,
				Versions: map[string]*VersionInfo{
					vi.Version:  &vi,
					vi2.Version: &vi2,
				},
			},
		}

		t.Run("initial-install", func(t *testing.T) {
			needsRestart, err := vc.UpdateBinary(t.Context(), SubsystemName)
			test.That(t, err, test.ShouldBeNil)
			test.That(t, needsRestart, test.ShouldBeTrue)
			testExists(t, filepath.Join(utils.ViamDirs.Bin, "viam-agent"))
			testExists(t, filepath.Join(utils.ViamDirs.Cache, "source-binary-"+vi.Version))
			test.That(t, vi.UnpackedPath, test.ShouldResemble, vi.DlPath)
		})

		t.Run("rerun-with-no-change", func(t *testing.T) {
			needsRestart, err := vc.UpdateBinary(t.Context(), SubsystemName)
			test.That(t, err, test.ShouldBeNil)
			test.That(t, needsRestart, test.ShouldBeFalse)
		})

		t.Run("upgrade", func(t *testing.T) {
			vc.ViamAgent.TargetVersion = vi2.Version
			needsRestart, err := vc.UpdateBinary(t.Context(), SubsystemName)
			test.That(t, err, test.ShouldBeNil)
			test.That(t, needsRestart, test.ShouldBeTrue)
			testExists(t, filepath.Join(utils.ViamDirs.Cache, "source-binary-"+vi2.Version))
		})

		t.Run("non-binary-file", func(t *testing.T) {
			nonBinaryPath := filepath.Join(td, "text.txt")
			err := os.WriteFile(nonBinaryPath, []byte("Hello, World!"), 0o644)
			test.That(t, err, test.ShouldBeNil)

			vi3 := vi2
			vi3.URL = "file://" + nonBinaryPath
			vi3.Version = "customURL+" + vi3.URL
			vi3.UnpackedSHA = make([]byte, 0)
			vc.ViamAgent.Versions[vi3.Version] = &vi3
			vc.ViamAgent.TargetVersion = vi3.Version

			needsRestart, err := vc.UpdateBinary(t.Context(), SubsystemName)
			test.That(t, needsRestart, test.ShouldBeFalse)
			test.That(t, err, test.ShouldNotBeNil)
			test.That(t, err.Error(), test.ShouldContainSubstring, "downloaded file does not appear to be a viam-agent binary")
			// Manually repair target for future subtests, as we just broke it by pointing to a
			// "bad" file.
			vc.ViamAgent.brokenTarget = false
		})

		t.Run("non-agent-binary-file", func(t *testing.T) {
			// We'll use the currently running test binary as an example of a non-agent binary.
			testBinaryPath, err := os.Executable()
			test.That(t, err, test.ShouldBeNil)

			vi4 := vi2
			vi4.URL = "file://" + testBinaryPath
			vi4.Version = "customURL+" + vi4.URL
			vi4.UnpackedSHA = make([]byte, 0)
			vc.ViamAgent.Versions[vi4.Version] = &vi4
			vc.ViamAgent.TargetVersion = vi4.Version

			needsRestart, err := vc.UpdateBinary(t.Context(), SubsystemName)
			test.That(t, needsRestart, test.ShouldBeFalse)
			test.That(t, err, test.ShouldNotBeNil)
			test.That(t, err.Error(), test.ShouldContainSubstring, "downloaded file does not appear to be a viam-agent binary")

			// Manually repair target for future subtests, as we just broke it by pointing to a
			// "bad" file.
			vc.ViamAgent.brokenTarget = false
		})

		t.Run("valid-file", func(t *testing.T) {
			// TODO(RSDK-12820): Remove this conditional once we support more agent features on
			// MacOS.
			if runtime.GOOS == "darwin" {
				t.Skip("Built viam-agent binary will not run -version on MacOS; skipping")
			}
			agentBinaryPath := utils.BuildViamAgent(t)

			vi5 := vi2
			vi5.URL = "file://" + agentBinaryPath
			vi5.Version = "customURL+" + vi5.URL
			vi5.UnpackedSHA = make([]byte, 0)
			vc.ViamAgent.Versions[vi5.Version] = &vi5
			vc.ViamAgent.TargetVersion = vi5.Version

			needsRestart, err := vc.UpdateBinary(t.Context(), SubsystemName)
			test.That(t, err, test.ShouldBeNil)
			test.That(t, needsRestart, test.ShouldBeTrue)
		})
	})
}

func TestUpdateBinaryAdoptRunningBinary(t *testing.T) {
	utils.MockAndCreateViamDirs(t)
	logger := logging.NewTestLogger(t)

	// A fake "currently running binary" with known contents. Resolve the temp dir since
	// adoption resolves symlinks (on darwin /var is a symlink to /private/var).
	td, err := filepath.EvalSymlinks(t.TempDir())
	test.That(t, err, test.ShouldBeNil)
	fakeExe := filepath.Join(td, "viam-agent-from-installer.exe")
	err = os.WriteFile(fakeExe, []byte("fake agent binary contents"), 0o755)
	test.That(t, err, test.ShouldBeNil)
	exeSHA, err := utils.GetFileSum(fakeExe)
	test.That(t, err, test.ShouldBeNil)

	oldOsExecutable := osExecutable
	osExecutable = func() (string, error) { return fakeExe, nil }
	t.Cleanup(func() { osExecutable = oldOsExecutable })

	t.Run("fresh-install-adopts", func(t *testing.T) {
		vi := &VersionInfo{
			Version: "0.99.0",
			// any attempted download would fail
			URL:         "file:///nonexistent/viam-agent-v0.99.0",
			UnpackedSHA: exeSHA,
			SymlinkPath: filepath.Join(utils.ViamDirs.Bin, "viam-agent"),
		}
		vc := VersionCache{
			logger:             logger,
			cacheCleanupLogger: logger,
			ViamAgent: &Versions{
				TargetVersion: vi.Version,
				Versions:      map[string]*VersionInfo{vi.Version: vi},
			},
		}

		needsRestart, err := vc.UpdateBinary(t.Context(), SubsystemName)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, needsRestart, test.ShouldBeFalse)
		test.That(t, vc.ViamAgent.CurrentVersion, test.ShouldEqual, vi.Version)
		test.That(t, vi.UnpackedPath, test.ShouldEqual, fakeExe)
		test.That(t, vi.DlPath, test.ShouldEqual, fakeExe)
		test.That(t, vi.Installed.IsZero(), test.ShouldBeFalse)
		linkTarget, err := filepath.EvalSymlinks(vi.SymlinkPath)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, linkTarget, test.ShouldEqual, fakeExe)

		// steady state afterwards: no download, no restart
		needsRestart, err = vc.UpdateBinary(t.Context(), SubsystemName)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, needsRestart, test.ShouldBeFalse)
	})

	t.Run("checksum-mismatch-downloads", func(t *testing.T) {
		sourceBinary := filepath.Join(td, "viam-agent-v0.99.1")
		err := os.WriteFile(sourceBinary, []byte("different contents"), 0o755)
		test.That(t, err, test.ShouldBeNil)
		sourceSHA, err := utils.GetFileSum(sourceBinary)
		test.That(t, err, test.ShouldBeNil)

		vi := &VersionInfo{
			Version:     "0.99.1",
			URL:         "file://" + sourceBinary,
			UnpackedSHA: sourceSHA,
			SymlinkPath: filepath.Join(utils.ViamDirs.Bin, "viam-agent"),
		}
		vc := VersionCache{
			logger:             logger,
			cacheCleanupLogger: logger,
			ViamAgent: &Versions{
				TargetVersion: vi.Version,
				Versions:      map[string]*VersionInfo{vi.Version: vi},
			},
		}

		// the running binary's checksum does not match the target, so this must download
		needsRestart, err := vc.UpdateBinary(t.Context(), SubsystemName)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, needsRestart, test.ShouldBeTrue)
		test.That(t, vc.ViamAgent.CurrentVersion, test.ShouldEqual, vi.Version)
		test.That(t, vi.UnpackedPath, test.ShouldNotEqual, fakeExe)
		testExists(t, filepath.Join(utils.ViamDirs.Cache, filepath.Base(vi.UnpackedPath)))
	})

	t.Run("viam-server-never-adopts", func(t *testing.T) {
		vi := &VersionInfo{
			Version:     "0.99.0",
			URL:         "file:///nonexistent/viam-server-v0.99.0",
			UnpackedSHA: exeSHA,
			SymlinkPath: filepath.Join(utils.ViamDirs.Bin, "viam-server"),
		}
		vc := VersionCache{
			logger:             logger,
			cacheCleanupLogger: logger,
			ViamServer: &Versions{
				TargetVersion: vi.Version,
				Versions:      map[string]*VersionInfo{vi.Version: vi},
			},
		}

		// even though the checksum matches the running executable, viam-server must
		// always be downloaded, so this errors on the unreachable URL
		needsRestart, err := vc.UpdateBinary(t.Context(), viamserver.SubsysName)
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "downloading")
		test.That(t, needsRestart, test.ShouldBeFalse)
		test.That(t, vc.ViamServer.CurrentVersion, test.ShouldEqual, "")
	})
}

// assert that a file exists.
func testExists(t *testing.T, path string) {
	t.Helper()
	_, err := os.Stat(path)
	test.That(t, err, test.ShouldBeNil)
}

// Download logging must distinguish a first fetch from a corrupt local copy (APP-15838), and
// a repair of the current version from an upgrade.
func TestUpdateBinaryDownloadLogs(t *testing.T) {
	utils.MockAndCreateViamDirs(t)
	logger, logs := logging.NewObservedTestLogger(t)

	// sha of an empty file
	emptySHA, err := hex.DecodeString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	test.That(t, err, test.ShouldBeNil)

	src := filepath.Join(t.TempDir(), "source-binary-0.70.0")
	test.That(t, os.WriteFile(src, nil, 0o600), test.ShouldBeNil)

	vi := VersionInfo{
		Version:     "0.70.0",
		URL:         "file://" + src,
		UnpackedSHA: emptySHA,
		SymlinkPath: filepath.Join(utils.ViamDirs.Bin, "viam-server"),
	}
	vc := VersionCache{
		logger:             logger,
		cacheCleanupLogger: logger,
		ViamServer: &Versions{
			TargetVersion: vi.Version,
			Versions:      map[string]*VersionInfo{vi.Version: &vi},
		},
	}

	// drains the observer first, so every count below covers just the one call
	update := func(t *testing.T) {
		t.Helper()
		logs.TakeAll()
		_, err := vc.UpdateBinary(t.Context(), viamserver.SubsysName)
		test.That(t, err, test.ShouldBeNil)
	}
	seen := func(snippet string) int { return logs.FilterMessageSnippet(snippet).Len() }

	t.Run("first-download", func(t *testing.T) {
		update(t)
		test.That(t, seen("no verified local copy"), test.ShouldEqual, 1)
		test.That(t, seen("new version ("), test.ShouldEqual, 1)
		test.That(t, seen("mismatched checksum"), test.ShouldEqual, 0)
		test.That(t, seen("reinstall"), test.ShouldEqual, 0)
	})

	// a corrupt copy of the version already installed is a repair, not an upgrade
	t.Run("corrupt-local-copy", func(t *testing.T) {
		test.That(t, vc.ViamServer.CurrentVersion, test.ShouldEqual, vi.Version)
		test.That(t, os.WriteFile(vi.UnpackedPath, []byte("bad contents"), 0o600), test.ShouldBeNil)
		update(t)
		test.That(t, seen("mismatched checksum"), test.ShouldEqual, 1)
		test.That(t, seen("reinstalling current version"), test.ShouldEqual, 1)
		test.That(t, seen("reinstalled at"), test.ShouldEqual, 1)
		test.That(t, seen("new version ("), test.ShouldEqual, 0)
	})

	// a custom URL's sha is wiped before the mismatch is logged, so the warning has to report
	// the sha captured ahead of that (APP-15838)
	t.Run("custom-url-mismatch", func(t *testing.T) {
		// the wiped sha sends the redownload back through validation, which needs a
		// natively executable fixture
		var magic []byte
		switch runtime.GOOS {
		case "linux":
			magic = []byte{0x7f, 'E', 'L', 'F'}
		case "darwin":
			magic = []byte{0xcf, 0xfa, 0xed, 0xfe}
		default:
			t.Skipf("no executable fixture for %s", runtime.GOOS)
		}

		src := filepath.Join(t.TempDir(), "custom-viam-server")
		test.That(t, os.WriteFile(src, magic, 0o700), test.ShouldBeNil)

		custom := VersionInfo{
			Version:     "customURL+file://" + src,
			URL:         "file://" + src,
			SymlinkPath: vi.SymlinkPath,
		}
		vc.ViamServer.Versions[custom.Version] = &custom
		vc.ViamServer.TargetVersion = custom.Version

		update(t)
		test.That(t, vc.ViamServer.PreviousVersion, test.ShouldEqual, vi.Version)
		installedSHA := custom.UnpackedSHA
		test.That(t, len(installedSHA), test.ShouldBeGreaterThan, 1)

		// corrupt the cached copy; the source is untouched, so the redownload restores it
		test.That(t, os.WriteFile(custom.UnpackedPath, append(magic, 'x'), 0o700), test.ShouldBeNil)
		update(t)

		warnings := logs.FilterMessageSnippet("mismatched checksum").All()
		test.That(t, len(warnings), test.ShouldEqual, 1)
		test.That(t, warnings[0].ContextMap()["expected"], test.ShouldEqual, hex.EncodeToString(installedSHA))

		// reinstalling the current version must leave the rollback target alone
		test.That(t, vc.ViamServer.CurrentVersion, test.ShouldEqual, custom.Version)
		test.That(t, vc.ViamServer.PreviousVersion, test.ShouldEqual, vi.Version)
	})
}

func TestGetProtectedFilesAndCleanVersions(t *testing.T) {
	t.Run("symlinks", func(t *testing.T) {
		utils.MockAndCreateViamDirs(t)
		vc := VersionCache{
			logger:             logging.NewTestLogger(t),
			cacheCleanupLogger: logging.NewTestLogger(t),
			ViamAgent:          &Versions{},
			ViamServer:         &Versions{},
		}

		expected := make([]string, len(baseProtectedFiles))
		copy(expected, baseProtectedFiles)
		// create symlinks
		for _, name := range []string{"viam-server", "viam-agent"} {
			path := filepath.Join(utils.ViamDirs.Cache, name)
			expected = append(expected, name)
			f, err := os.Create(path)
			test.That(t, err, test.ShouldBeNil)
			test.That(t, f.Close(), test.ShouldBeNil)
			linkPath := filepath.Join(utils.ViamDirs.Bin, name)
			if runtime.GOOS == "windows" {
				linkPath += ".exe"
			}
			utils.ForceSymlink(path, linkPath)
		}
		protected := vc.getProtectedFilesAndCleanVersions(t.Context(), 1)
		slices.Sort(expected)
		slices.Sort(protected)
		test.That(t, protected, test.ShouldResemble, expected)
	})

	t.Run("expired", func(t *testing.T) {
		utils.MockAndCreateViamDirs(t)
		vc := VersionCache{
			logger:             logging.NewTestLogger(t),
			cacheCleanupLogger: logging.NewTestLogger(t),
			ViamAgent:          &Versions{},
			ViamServer: &Versions{
				PreviousVersion: "prev",
				TargetVersion:   "target",
				runningVersion:  "running",
				Versions: map[string]*VersionInfo{
					"prev":    {UnpackedPath: "prev"},
					"target":  {UnpackedPath: "target"},
					"running": {UnpackedPath: "running"},
					"recent":  {UnpackedPath: "recent", Installed: time.Now().Add(time.Hour * -23)},
					"stale":   {UnpackedPath: "stale", Installed: time.Now().Add(time.Hour * -25)},
				},
			},
		}

		expected := make([]string, len(baseProtectedFiles))
		copy(expected, baseProtectedFiles)
		expected = append(expected, "prev", "target", "running", "recent") // not "stale" though

		protected := vc.getProtectedFilesAndCleanVersions(t.Context(), 1)
		slices.Sort(expected)
		slices.Sort(protected)
		test.That(t, protected, test.ShouldResemble, expected)

		// confirm that 'stale' was removed from versions list
		test.That(t, vc.ViamServer.Versions, test.ShouldHaveLength, 4)
		test.That(t, vc.ViamServer.Versions["stale"], test.ShouldBeNil)
	})
}

func TestCleanPartials(t *testing.T) {
	utils.MockAndCreateViamDirs(t)
	vc := VersionCache{
		logger:             logging.NewTestLogger(t),
		cacheCleanupLogger: logging.NewTestLogger(t),
	}

	// make a part file to clean up
	oldPath, _ := utils.CreatePartialPath("https://viam.com/old.part")
	err := os.Mkdir(filepath.Dir(oldPath), 0o755)
	test.That(t, err, test.ShouldBeNil)
	err = os.WriteFile(oldPath, []byte("hello"), 0o600)
	test.That(t, err, test.ShouldBeNil)
	os.Chtimes(oldPath, time.Now(), time.Now().Add(-time.Hour*24*4))

	// make another one too new to clean up
	newPath, _ := utils.CreatePartialPath("https://viam.com/subpath/new.part")
	err = os.Mkdir(filepath.Dir(newPath), 0o755)
	test.That(t, err, test.ShouldBeNil)
	err = os.WriteFile(newPath, []byte("hello"), 0o600)
	test.That(t, err, test.ShouldBeNil)

	err = vc.CleanPartials(t.Context())
	test.That(t, err, test.ShouldBeNil)

	// old path should be gone, newpath should still exist
	_, err = os.Stat(oldPath)
	var pathError *os.PathError
	test.That(t, errors.As(err, &pathError), test.ShouldBeTrue)
	_, err = os.Stat(newPath)
	test.That(t, err, test.ShouldBeNil)
}

func TestVersionCacheJSONRoundtrip(t *testing.T) {
	someTime, err := time.Parse("2006-01-02 15:04:05", "2011-11-11 00:00:00" /* https://tinyurl.com/dm4ytr3c */)
	test.That(t, err, test.ShouldBeNil)
	vc := &VersionCache{
		ViamAgent: &Versions{
			PreviousVersion: "prev",
			TargetVersion:   "target",
			Versions: map[string]*VersionInfo{
				"prev":    {UnpackedPath: "prev"},
				"target":  {UnpackedPath: "target"},
				"running": {UnpackedPath: "running"},
				"recent":  {UnpackedPath: "recent", Installed: someTime.Add(time.Hour * -23)},
				"stale":   {UnpackedPath: "stale", Installed: someTime.Add(time.Hour * -25)},
			},
		},
		ViamServer: &Versions{
			PreviousVersion: "prev",
			TargetVersion:   "target",
			Versions: map[string]*VersionInfo{
				"prev":    {UnpackedPath: "prev"},
				"target":  {UnpackedPath: "target"},
				"running": {UnpackedPath: "running"},
				"recent":  {UnpackedPath: "recent", Installed: someTime.Add(time.Hour * -23)},
				"stale":   {UnpackedPath: "stale", Installed: someTime.Add(time.Hour * -25)},
			},
		},
		LastCleaned: someTime.Add(time.Hour * -1),
	}

	jsonBytes, err := json.Marshal(vc)
	test.That(t, err, test.ShouldBeNil)

	var unmarshaledVC VersionCache
	test.That(t, json.Unmarshal(jsonBytes, &unmarshaledVC), test.ShouldBeNil)

	test.That(t, &unmarshaledVC, test.ShouldResemble, vc)
}
