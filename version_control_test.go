package agent

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/viamrobotics/agent/subsystems/viamserver"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
	"go.viam.com/test"
)

// replace utils.ViamDirs with t.TempDir for duration of test.
func mockViamDirs(t *testing.T) {
	t.Helper()
	old := utils.ViamDirs
	t.Cleanup(func() {
		utils.ViamDirs = old
	})
	td := t.TempDir()
	utils.ViamDirs = map[string]string{
		"viam": td,
	}
	for _, subdir := range []string{"bin", "cache", "tmp", "etc"} {
		utils.ViamDirs[subdir] = filepath.Join(td, subdir)
		os.Mkdir(utils.ViamDirs[subdir], 0o755)
	}
}

func TestUpdateBinary(t *testing.T) {
	mockViamDirs(t)
	logger := logging.NewTestLogger(t)

	vi := VersionInfo{
		Version:     "0.70.0",
		SymlinkPath: filepath.Join(utils.ViamDirs["bin"], "viam-server"),
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
	testExists(t, filepath.Join(utils.ViamDirs["bin"], "viam-server"))
	testExists(t, filepath.Join(utils.ViamDirs["cache"], "source-binary-"+vi.Version))
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
	testExists(t, filepath.Join(utils.ViamDirs["cache"], "source-binary-"+vi2.Version))

	// todo: test custom URL
}

// assert that a file exists
func testExists(t *testing.T, path string) {
	t.Helper()
	_, err := os.Stat(path)
	test.That(t, err, test.ShouldBeNil)
}
