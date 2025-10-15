package agent

import (
	"context"
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

	// initial install
	needsRestart, err := vc.UpdateBinary(context.Background(), viamserver.SubsysName)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, needsRestart, test.ShouldBeTrue)
	testExists(t, filepath.Join(utils.ViamDirs.Bin, "viam-server"))
	testExists(t, filepath.Join(utils.ViamDirs.Cache, "source-binary-"+vi.Version))
	test.That(t, vi.UnpackedPath, test.ShouldResemble, vi.DlPath)

	// rerun with no change
	needsRestart, err = vc.UpdateBinary(context.Background(), viamserver.SubsysName)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, needsRestart, test.ShouldBeFalse)

	// upgrade
	vc.ViamServer.TargetVersion = vi2.Version
	needsRestart, err = vc.UpdateBinary(context.Background(), viamserver.SubsysName)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, needsRestart, test.ShouldBeTrue)
	testExists(t, filepath.Join(utils.ViamDirs.Cache, "source-binary-"+vi2.Version))

	// todo: test custom URL
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
		protected := vc.getProtectedFilesAndCleanVersions(context.Background(), 1)
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

		protected := vc.getProtectedFilesAndCleanVersions(context.Background(), 1)
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
	oldPath := filepath.Join(utils.ViamDirs.Partials, "abc1", "old.part")
	err := os.Mkdir(filepath.Dir(oldPath), 0o755)
	test.That(t, err, test.ShouldBeNil)
	err = os.WriteFile(oldPath, []byte("hello"), 0o600)
	test.That(t, err, test.ShouldBeNil)
	os.Chtimes(oldPath, time.Now(), time.Now().Add(-time.Hour*24*4))

	// make another one too new to clean up
	newPath := filepath.Join(utils.ViamDirs.Partials, "abc2", "new.part")
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
