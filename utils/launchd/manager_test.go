package launchd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
	"go.viam.com/test"
)

// Fake property list for testing purposes.
var myPlistBytes = []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.viam.test</string>
	<key>ProgramArguments</key>
	<array>
		<string>/usr/bin/false</string>
	</array>
</dict>
</plist>
`)

func TestLaunchdManagerInstallService(t *testing.T) {
	// Asserts that appropriate launchd executor methods are called by InstallService and
	// the method itself returns appropriate values.

	tests := []struct {
		name                string
		previousFileExists  bool
		previousFileHasDiff bool
	}{
		{
			name: "new install",
		},
		{
			name:               "identical existing install",
			previousFileExists: true,
		},
		{
			name:                "changed existing install",
			previousFileExists:  true,
			previousFileHasDiff: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := logging.NewTestLogger(t)
			td := t.TempDir()
			serviceDir := filepath.Join(td, "LaunchDaemons")
			err := os.MkdirAll(serviceDir, 0o755)
			test.That(t, err, test.ShouldBeNil)

			executor := &fakeExecutor{}
			manager := NewLaunchdManager(logger)
			manager.privateExecutor = executor
			manager.serviceDir = serviceDir

			if tc.previousFileExists {
				serviceFilePath := filepath.Join(serviceDir, "my-service.plist")
				if tc.previousFileHasDiff {
					utils.Touch(t, serviceFilePath)
				} else {
					err := os.WriteFile(serviceFilePath, myPlistBytes, 0o644)
					test.That(t, err, test.ShouldBeNil)
				}
			}

			serviceFile, newInstall, err := manager.InstallService(t.Context(), "my-service", myPlistBytes)
			test.That(t, err, test.ShouldBeNil)
			test.That(t, serviceFile, test.ShouldEqual, filepath.Join(serviceDir, "my-service.plist"))
			test.That(t, newInstall, test.ShouldEqual, !tc.previousFileExists)

			// Kickstart is always called.
			test.That(t, executor.kickstartCallCount, test.ShouldEqual, 1)

			switch {
			case !tc.previousFileExists:
				// New install: bootstrap called, bootout not called.
				test.That(t, executor.bootstrapCallCount, test.ShouldEqual, 1)
				test.That(t, executor.bootoutCallCount, test.ShouldEqual, 0)
			case tc.previousFileHasDiff:
				// Changed existing: bootout and bootstrap both called.
				test.That(t, executor.bootoutCallCount, test.ShouldEqual, 1)
				test.That(t, executor.bootstrapCallCount, test.ShouldEqual, 1)
			default:
				// Identical existing: no bootout, no bootstrap (only kickstart).
				test.That(t, executor.bootoutCallCount, test.ShouldEqual, 0)
				test.That(t, executor.bootstrapCallCount, test.ShouldEqual, 0)
			}
		})
	}
}

type fakeExecutor struct {
	bootstrapCallCount int
	bootoutCallCount   int
	kickstartCallCount int
}

// Bootstrap implements LaunchdExecutor.
func (f *fakeExecutor) Bootstrap(_ context.Context, _ string) error {
	f.bootstrapCallCount++
	return nil
}

// Bootout implements LaunchdExecutor.
func (f *fakeExecutor) Bootout(_ context.Context, _ string) error {
	f.bootoutCallCount++
	return nil
}

// Enable implements LaunchdExecutor.
func (f *fakeExecutor) Enable(_ context.Context, _ string) error {
	return nil
}

// IsAvailable implements LaunchdExecutor.
func (f *fakeExecutor) IsAvailable(_ context.Context) error {
	return nil
}

// IsServiceRemoved implements LaunchdExecutor.
func (f *fakeExecutor) IsServiceRemoved(_ context.Context, _ string) bool {
	// Always return true so the wait loop in InstallService exits immediately.
	return true
}

// Kickstart implements LaunchdExecutor.
func (f *fakeExecutor) Kickstart(_ context.Context, _ string, _ bool) error {
	f.kickstartCallCount++
	return nil
}
