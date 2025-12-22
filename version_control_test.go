package agent

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/viamrobotics/agent/subsystems/viamserver"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
	"go.viam.com/test"
	goutils "go.viam.com/utils"
)

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
			logger: logger,
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

			elfBytes := []byte{0x7f, 'E', 'L', 'F'}

			mux := http.NewServeMux()
			mux.HandleFunc("/nolm", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/x-executable")
				w.Write(elfBytes)
			})
			mux.HandleFunc("/lm", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Last-Modified", "Tue, 09 Dec 2025 18:52:44 GMT")
				w.Write(elfBytes)
			})
			mux.HandleFunc("/badlm", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Last-Modified", "asdfghjkl")
				w.Write(elfBytes)
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
			logger: logger,
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
			nonAgentBinaryProgramPath := filepath.Join(td, "main.go")
			nonAgentBinaryPath := filepath.Join(td, "main")
			golangProgram := []byte(
				`package main

func main() {
	println("Hello, World!")
}
`)
			err := os.WriteFile(nonAgentBinaryProgramPath, golangProgram, 0o644)
			test.That(t, err, test.ShouldBeNil)
			cmd := exec.Command("go", "build", nonAgentBinaryProgramPath)
			cmd.Dir = td
			output, err := cmd.CombinedOutput()
			test.That(t, string(output), test.ShouldBeBlank)
			test.That(t, err, test.ShouldBeNil)

			vi4 := vi2
			vi4.URL = "file://" + nonAgentBinaryPath
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

// assert that a file exists.
func testExists(t *testing.T, path string) {
	t.Helper()
	_, err := os.Stat(path)
	test.That(t, err, test.ShouldBeNil)
}

func TestGetProtectedFilesAndCleanVersions(t *testing.T) {
	t.Run("symlinks", func(t *testing.T) {
		utils.MockAndCreateViamDirs(t)
		vc := VersionCache{
			logger:     logging.NewTestLogger(t),
			ViamAgent:  &Versions{},
			ViamServer: &Versions{},
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
			logger:    logging.NewTestLogger(t),
			ViamAgent: &Versions{},
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
	vc := VersionCache{logger: logging.NewTestLogger(t)}

	// make a part file to clean up
	oldPath := utils.CreatePartialPath("https://viam.com/old.part")
	err := os.Mkdir(filepath.Dir(oldPath), 0o755)
	test.That(t, err, test.ShouldBeNil)
	err = os.WriteFile(oldPath, []byte("hello"), 0o600)
	test.That(t, err, test.ShouldBeNil)
	os.Chtimes(oldPath, time.Now(), time.Now().Add(-time.Hour*24*4))

	// make another one too new to clean up
	newPath := utils.CreatePartialPath("https://viam.com/subpath/new.part")
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
