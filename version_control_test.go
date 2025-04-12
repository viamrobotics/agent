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

	f, err := os.Create(filepath.Join(t.TempDir(), "source-binary"))
	test.That(t, err, test.ShouldBeNil)
	f.Close()

	vi := &VersionInfo{
		Version:     "0.70.0",
		URL:         "file://" + f.Name(),
		SymlinkPath: filepath.Join(utils.ViamDirs["bin"], "viam-server"),
	}
	// sha of an empty file
	vi.UnpackedSHA, err = hex.DecodeString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	test.That(t, err, test.ShouldBeNil)
	vc := VersionCache{
		logger: logger,
		ViamServer: &Versions{
			TargetVersion:  "0.70.0",
			CurrentVersion: "",
			Versions: map[string]*VersionInfo{
				"0.70.0": vi,
			},
		},
	}

	// initial install
	needsRestart, err := vc.UpdateBinary(context.Background(), viamserver.SubsysName)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, needsRestart, test.ShouldBeTrue)
	_, err = os.Stat(filepath.Join(utils.ViamDirs["bin"], "viam-server"))
	test.That(t, err, test.ShouldBeNil)
	_, err = os.Stat(filepath.Join(utils.ViamDirs["cache"], "source-binary"))
	test.That(t, err, test.ShouldBeNil)
	test.That(t, vi.UnpackedPath, test.ShouldResemble, vi.DlPath)

	// rerun with no change
	needsRestart, err = vc.UpdateBinary(context.Background(), viamserver.SubsysName)
	test.That(t, err, test.ShouldBeNil)
	test.That(t, needsRestart, test.ShouldBeFalse)

	// todo: test upgrade case
}

/*
// VersionInfo records details about each version of a subsystem.
type VersionInfo struct {
	Version      string
	URL          string
	DlPath       string
	DlSHA        []byte
	UnpackedPath string
	UnpackedSHA  []byte
	SymlinkPath  string
	Installed    time.Time
}*/
