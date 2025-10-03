package agent_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/viamrobotics/agent"
	"github.com/viamrobotics/agent/utils"
	pb "go.viam.com/api/app/agent/v1"
	"go.viam.com/rdk/logging"
	"go.viam.com/test"
)

func TestInstall(t *testing.T) {
	t.Run("fail systemd not available", func(t *testing.T) {
		utils.MockViamDirs(t)
		logger := logging.NewTestLogger(t)
		systemdManager := &fakeSystemdManager{unavailable: true}
		err := agent.Install(logger, systemdManager)
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "can only install on systems using systemd")
	})

	t.Run("fresh install", func(t *testing.T) {
		// For fresh installs we expect to install the binary, symlink it, and write
		// out a minimal version cache so agent knows it doesn't need to self
		// update on its first run.
		const fakeVersion = "0.22.0"
		const fakeRevision = "fakeGitSha"
		utils.MockBuildInfo(t, fakeVersion, fakeRevision)
		utils.MockViamDirs(t)
		logger := logging.NewTestLogger(t)

		systemdManager := &fakeSystemdManager{isNewInstall: true}
		err := agent.Install(logger, systemdManager)
		test.That(t, err, test.ShouldBeNil)

		expectedCachePath := filepath.Join(
			utils.ViamDirs.Cache,
			strings.Join([]string{
				"viam-agent",
				"v" + utils.Version,
				utils.GoArchToOSArch(runtime.GOARCH),
			},
				"-",
			),
		)
		_, err = os.Stat(expectedCachePath)
		test.That(t, err, test.ShouldBeNil)

		expectedBinPath := filepath.Join(utils.ViamDirs.Bin, "viam-agent")
		binLinksToCache, err := utils.CheckIfSame(expectedBinPath, expectedCachePath)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, binLinksToCache, test.ShouldBeTrue)

		test.That(t, agent.VersionCacheExists(), test.ShouldBeTrue)
		versionCache := agent.NewVersionCache(logger)
		test.That(t, versionCache.ViamAgent.CurrentVersion, test.ShouldEqual, fakeVersion)
		test.That(t, versionCache.ViamAgent.Versions, test.ShouldHaveLength, 1)
		version := versionCache.ViamAgent.Versions[fakeVersion]
		test.That(t, version.Version, test.ShouldEqual, fakeVersion)
		test.That(t, version.UnpackedPath, test.ShouldEqual, expectedCachePath)
		test.That(t, version.DlPath, test.ShouldEqual, expectedCachePath)
		test.That(t, version.SymlinkPath, test.ShouldEqual, expectedBinPath)

		test.That(t, systemdManager.enableCallCount, test.ShouldEqual, 1)
	})

	t.Run("self update", func(t *testing.T) {
		// If run as part of a self update, as determined by a version cache
		// existing on disk, we just install the binary but don't touch the version
		// cache.
		const fakeVersion = "0.22.0"
		const fakeRevision = "fakeGitSha"
		// This would not happen in a real run but we want to use a different
		// version string here so we can verify the install function didn't
		// overwrite it.
		const altVersion = "0.22.0-alt"
		const altURL = "https://example.com/agent"
		utils.MockAndCreateViamDirs(t)
		utils.MockBuildInfo(t, fakeVersion, fakeRevision)
		logger := logging.NewTestLogger(t)

		oldVersionCache := agent.NewVersionCache(logger)
		oldVersionCache.Update(&pb.UpdateInfo{
			Version: altVersion,
			Url:     altURL,
		}, "viam-agent")
		// Sanity check to confirm the cache was written to disk.
		test.That(t, agent.VersionCacheExists(), test.ShouldBeTrue)

		systemdManager := &fakeSystemdManager{}
		err := agent.Install(logger, systemdManager)
		test.That(t, err, test.ShouldBeNil)

		expectedCachePath := filepath.Join(
			utils.ViamDirs.Cache,
			strings.Join([]string{
				"viam-agent",
				"v" + utils.Version,
				utils.GoArchToOSArch(runtime.GOARCH),
			},
				"-",
			),
		)
		_, err = os.Stat(expectedCachePath)
		test.That(t, err, test.ShouldBeNil)

		expectedBinPath := filepath.Join(utils.ViamDirs.Bin, "viam-agent")
		binLinksToCache, err := utils.CheckIfSame(expectedBinPath, expectedCachePath)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, binLinksToCache, test.ShouldBeTrue)

		test.That(t, agent.VersionCacheExists(), test.ShouldBeTrue)
		versionCache := agent.NewVersionCache(logger)
		test.That(t, versionCache.ViamAgent.TargetVersion, test.ShouldEqual, altVersion)
		test.That(t, versionCache.ViamAgent.Versions, test.ShouldHaveLength, 1)
		version := versionCache.ViamAgent.Versions[altVersion]
		test.That(t, version.Version, test.ShouldEqual, altVersion)
		test.That(t, version.URL, test.ShouldEqual, altURL)

		test.That(t, systemdManager.enableCallCount, test.ShouldEqual, 0)
	})
}

type fakeSystemdManager struct {
	unavailable     bool
	enableCallCount int
	isNewInstall    bool
}

func (f *fakeSystemdManager) Enable(serviceName string) error {
	f.enableCallCount += 1
	return nil
}

func (f *fakeSystemdManager) InstallService(serviceName string, serviceFileContents []byte) (string, bool, error) {
	return "", f.isNewInstall, nil
}

func (f *fakeSystemdManager) IsAvailable() error {
	if f.unavailable {
		return errors.New("systemd unavailable")
	}
	return nil
}
