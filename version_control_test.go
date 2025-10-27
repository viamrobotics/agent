package agent

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/viamrobotics/agent/subsystems/viamserver"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
	"go.viam.com/test"
)

func TestUpdateBinary(t *testing.T) {
	utils.MockAndCreateViamDirs(t)
	logger := logging.NewTestLogger(t)

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

		// Note: we leave the bad file there rather than deleting it when the checksum fails.
		// The agent event loop should prevent it from being used because the cache isn't saved?
		// _, err = os.Stat(vi4.UnpackedPath)
		// test.That(t, os.IsNotExist(err), test.ShouldBeTrue)
	})

	t.Run("custom-url", func(t *testing.T) {
		t.Skip("todo")
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
