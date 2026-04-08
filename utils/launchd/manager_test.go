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
		name                   string
		serviceInstalled       bool
		previousFileExists     bool
		previousFileHasDiff    bool
		expectedNewInstall     bool
		expectedKickstartCount int
		expectedBootoutCount   int
		expectedBootstrapCount int
	}{
		{
			name:                   "new install",
			expectedNewInstall:     true,
			expectedKickstartCount: 1,
			expectedBootoutCount:   0,
			expectedBootstrapCount: 1,
		},
		{
			name:                   "identical existing install",
			serviceInstalled:       true,
			previousFileExists:     true,
			expectedNewInstall:     false,
			expectedKickstartCount: 0,
			expectedBootoutCount:   0,
			expectedBootstrapCount: 0,
		},
		{
			name:                   "changed existing install",
			serviceInstalled:       true,
			previousFileExists:     true,
			previousFileHasDiff:    true,
			expectedNewInstall:     false,
			expectedKickstartCount: 1,
			expectedBootoutCount:   1,
			expectedBootstrapCount: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logger := logging.NewTestLogger(t)
			td := t.TempDir()
			serviceDir := filepath.Join(td, "LaunchDaemons")
			err := os.MkdirAll(serviceDir, 0o755)
			test.That(t, err, test.ShouldBeNil)

			executor := &fakeExecutor{serviceInstalled: tc.serviceInstalled}
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
			test.That(t, newInstall, test.ShouldEqual, tc.expectedNewInstall)

			test.That(t, executor.kickstartCallCount, test.ShouldEqual, tc.expectedKickstartCount)
			test.That(t, executor.bootoutCallCount, test.ShouldEqual, tc.expectedBootoutCount)
			test.That(t, executor.bootstrapCallCount, test.ShouldEqual, tc.expectedBootstrapCount)
		})
	}
}

type fakeExecutor struct {
	bootstrapCallCount int
	bootoutCallCount   int
	kickstartCallCount int
	serviceInstalled   bool
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
	// Return false (service present) until bootout is called, then true so the wait loop exits.
	return !f.serviceInstalled || f.bootoutCallCount > 0
}

// Kickstart implements LaunchdExecutor.
func (f *fakeExecutor) Kickstart(_ context.Context, _ string, _ bool) error {
	f.kickstartCallCount++
	return nil
}
