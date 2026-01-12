package systemd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
	"go.viam.com/test"
)

var myServiceBytes = []byte(`
[Unit]
Description=Fake test service

[Service]
Type=exec
ExecStart=/usr/bin/false
`)

type previousServiceFileState struct {
	exists     bool
	inFallback bool
	hasDiff    bool
}

type installServiceTestRow struct {
	name                 string
	includeNewSearchPath bool
	previousServiceFile  previousServiceFileState
}

func TestSystemdManagerInstallService(t *testing.T) {
	tests := []installServiceTestRow{
		{
			name:                 "new install in default directory",
			includeNewSearchPath: true,
		},
		{
			name:                 "new install in fallback directory",
			includeNewSearchPath: false,
		},
		{
			name:                 "identical install in default directory",
			includeNewSearchPath: true,
			previousServiceFile: previousServiceFileState{
				exists: true,
			},
		},
		{
			name:                 "outdated install in default directory",
			includeNewSearchPath: true,
			previousServiceFile: previousServiceFileState{
				exists:  true,
				hasDiff: true,
			},
		},
		{
			name:                 "identical install in fallback directory",
			includeNewSearchPath: true,
			previousServiceFile: previousServiceFileState{
				exists:     true,
				inFallback: true,
			},
		},
		{
			name:                 "outdated install in fallback directory",
			includeNewSearchPath: true,
			previousServiceFile: previousServiceFileState{
				exists:     true,
				hasDiff:    true,
				inFallback: true,
			},
		},
	}

	for _, tc := range tests {
		const serviceName = "my-service"
		expectedServiceFileName := serviceName + ".service"
		t.Run(tc.name, func(t *testing.T) {
			logger := logging.NewTestLogger(t)
			td := t.TempDir()
			defaultServiceDir := filepath.Join(td, "defaultServiceDir")
			fallbackServiceDir := filepath.Join(td, "fallbackServiceDir")
			executor := &fakeExecutor{
				searchPaths: []string{fallbackServiceDir},
			}
			if tc.includeNewSearchPath {
				executor.searchPaths = []string{defaultServiceDir, fallbackServiceDir}
			}
			if tc.previousServiceFile.exists {
				dir := defaultServiceDir
				if tc.previousServiceFile.inFallback {
					dir = fallbackServiceDir
				}
				err := os.MkdirAll(dir, 0o755)
				test.That(t, err, test.ShouldBeNil)
				serviceFilePath := filepath.Join(dir, expectedServiceFileName)
				if tc.previousServiceFile.hasDiff {
					utils.Touch(t, serviceFilePath)
				} else {
					os.WriteFile(serviceFilePath, myServiceBytes, 0o644)
				}
			}
			manager := NewSystemdManager(logger)
			manager.privateExecutor = executor
			manager.dirs = systemdDirs{
				serviceFileDir:  defaultServiceDir,
				fallbackFileDir: fallbackServiceDir,
			}

			serviceFile, newInstall, err := manager.InstallService(t.Context(), "my-service", myServiceBytes)
			test.That(t, err, test.ShouldBeNil)

			if !tc.previousServiceFile.exists || tc.previousServiceFile.hasDiff || tc.previousServiceFile.inFallback {
				// All of these conditions lead to modifying the service file in some
				// way, leading to systemd needing to reload it: it never existed, it
				// existed but had differing contents, it existed with any contents but
				// we migrated it from the old fallback directory.
				test.That(t, executor.daemonReloadCallCount, test.ShouldEqual, 1)
			} else {
				test.That(t, executor.daemonReloadCallCount, test.ShouldEqual, 0)
			}

			test.That(t, newInstall, test.ShouldEqual, !tc.previousServiceFile.exists)

			if tc.includeNewSearchPath {
				test.That(t, serviceFile, test.ShouldEqual, filepath.Join(defaultServiceDir, "my-service.service"))
			} else {
				test.That(t, serviceFile, test.ShouldEqual, filepath.Join(fallbackServiceDir, "my-service.service"))
			}
		})
	}
}

type fakeExecutor struct {
	searchPaths           []string
	daemonReloadCallCount int
}

// DaemonReload implements systemd.SystemdExecutor.
func (f *fakeExecutor) DaemonReload(context.Context) error {
	f.daemonReloadCallCount += 1
	return nil
}

// Enable implements systemd.SystemdExecutor.
func (f *fakeExecutor) Enable(ctx context.Context, service string) error {
	return nil
}

// IsAvailable implements systemd.SystemdExecutor.
func (f *fakeExecutor) IsAvailable(context.Context) error {
	return nil
}

// SystemdSearchPaths implements systemd.SystemdExecutor.
func (f *fakeExecutor) SystemdSearchPaths(context.Context) ([]string, error) {
	return f.searchPaths, nil
}
