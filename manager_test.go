package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/viamrobotics/agent/subsystems/networking"
	"github.com/viamrobotics/agent/subsystems/syscfg"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
	"go.viam.com/test"
	"google.golang.org/protobuf/types/known/durationpb"
)

// fakeViamServer is a test double for viamServerSubsystem. Each method's
// behavior is controlled by an overridable func; defaults are inert.
type fakeViamServer struct {
	startFn          func(ctx context.Context) error
	stopFn           func(ctx context.Context) error
	updateFn         func(ctx context.Context, cfg utils.AgentConfig) bool
	restartAllowedFn func(ctx context.Context) bool

	startCalls int
	stopCalls  int
}

func (f *fakeViamServer) Start(ctx context.Context) error {
	f.startCalls++
	if f.startFn != nil {
		return f.startFn(ctx)
	}
	return nil
}

func (f *fakeViamServer) Stop(ctx context.Context) error {
	f.stopCalls++
	if f.stopFn != nil {
		return f.stopFn(ctx)
	}
	return nil
}

func (f *fakeViamServer) Update(ctx context.Context, cfg utils.AgentConfig) bool {
	if f.updateFn != nil {
		return f.updateFn(ctx, cfg)
	}
	return false
}

func (f *fakeViamServer) RestartAllowed(ctx context.Context) bool {
	if f.restartAllowedFn != nil {
		return f.restartAllowedFn(ctx)
	}
	return true
}

func (f *fakeViamServer) DoesNotHandleNeedsRestart() bool { return true }
func (f *fakeViamServer) MarkAppTriggeredRestart()        {}
func (f *fakeViamServer) Uptime() *durationpb.Duration    { return nil }

func TestLoadAppConfig(t *testing.T) {
	// Helper to create a minimal manager for testing
	createTestManager := func(t *testing.T) *Manager {
		t.Helper()
		logger := logging.NewTestLogger(t)
		return &Manager{
			logger: logger,
		}
	}

	// Helper to mock AppConfigFilePath and write test content
	setupConfigFile := func(t *testing.T, content string) {
		t.Helper()
		tmpDir := t.TempDir()
		configPath := filepath.Join(tmpDir, "viam.json")
		err := os.WriteFile(configPath, []byte(content), 0o644)
		test.That(t, err, test.ShouldBeNil)

		originalPath := utils.AppConfigFilePath
		utils.AppConfigFilePath = configPath
		t.Cleanup(func() {
			utils.AppConfigFilePath = originalPath
		})
	}

	t.Run("happy path with api_key", func(t *testing.T) {
		setupConfigFile(t, `{
			"cloud": {
				"id": "robot-id",
				"app_address": "https://app.viam.com",
				"api_key": {
					"id": "api-key-id",
					"key": "api-key-secret"
				}
			}
		}`)

		m := createTestManager(t)
		err := m.LoadAppConfig()
		test.That(t, err, test.ShouldBeNil)
		test.That(t, m.cloudConfig, test.ShouldNotBeNil)
		test.That(t, m.cloudConfig.AppAddress, test.ShouldEqual, "https://app.viam.com")
		test.That(t, m.cloudConfig.ID, test.ShouldEqual, "robot-id")
		test.That(t, m.cloudConfig.CloudCred, test.ShouldNotBeNil)
	})

	t.Run("happy path with secret", func(t *testing.T) {
		setupConfigFile(t, `{
			"cloud": {
				"id": "robot-id",
				"app_address": "https://app.viam.com",
				"secret": "robot-secret"
			}
		}`)

		m := createTestManager(t)
		err := m.LoadAppConfig()
		test.That(t, err, test.ShouldBeNil)
		test.That(t, m.cloudConfig, test.ShouldNotBeNil)
		test.That(t, m.cloudConfig.AppAddress, test.ShouldEqual, "https://app.viam.com")
		test.That(t, m.cloudConfig.ID, test.ShouldEqual, "robot-id")
		test.That(t, m.cloudConfig.CloudCred, test.ShouldNotBeNil)
	})

	t.Run("file not found", func(t *testing.T) {
		originalPath := utils.AppConfigFilePath
		utils.AppConfigFilePath = "/nonexistent/path/viam.json"
		t.Cleanup(func() {
			utils.AppConfigFilePath = originalPath
		})

		m := createTestManager(t)
		err := m.LoadAppConfig()
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "reading config file")
	})

	t.Run("invalid JSON", func(t *testing.T) {
		setupConfigFile(t, `{invalid json}`)

		m := createTestManager(t)
		err := m.LoadAppConfig()
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "parsing config file")
	})

	t.Run("missing cloud section", func(t *testing.T) {
		setupConfigFile(t, `{
			"some_other_field": "value"
		}`)

		m := createTestManager(t)
		err := m.LoadAppConfig()
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "no cloud section in local config file")
	})

	t.Run("cloud section is not an object", func(t *testing.T) {
		setupConfigFile(t, `{
			"cloud": "not-an-object"
		}`)

		m := createTestManager(t)
		err := m.LoadAppConfig()
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "no cloud section in local config file")
	})

	t.Run("missing app_address", func(t *testing.T) {
		setupConfigFile(t, `{
			"cloud": {
				"id": "robot-id",
				"secret": "robot-secret"
			}
		}`)

		m := createTestManager(t)
		err := m.LoadAppConfig()
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "field 'app_address' in cloud config must be a non-empty string")
	})

	t.Run("empty app_address", func(t *testing.T) {
		setupConfigFile(t, `{
			"cloud": {
				"id": "robot-id",
				"app_address": "",
				"secret": "robot-secret"
			}
		}`)

		m := createTestManager(t)
		err := m.LoadAppConfig()
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "field 'app_address' in cloud config must be a non-empty string")
	})

	t.Run("missing id in cloud section", func(t *testing.T) {
		setupConfigFile(t, `{
			"cloud": {
				"app_address": "https://app.viam.com",
				"secret": "robot-secret"
			}
		}`)

		m := createTestManager(t)
		err := m.LoadAppConfig()
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "field 'id' in cloud config must be a non-empty string")
	})

	t.Run("empty id in cloud section", func(t *testing.T) {
		setupConfigFile(t, `{
			"cloud": {
				"id": "",
				"app_address": "https://app.viam.com",
				"secret": "robot-secret"
			}
		}`)

		m := createTestManager(t)
		err := m.LoadAppConfig()
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "field 'id' in cloud config must be a non-empty string")
	})

	t.Run("invalid credentials (no api_key or secret)", func(t *testing.T) {
		setupConfigFile(t, `{
			"cloud": {
				"id": "robot-id",
				"app_address": "https://app.viam.com"
			}
		}`)

		m := createTestManager(t)
		err := m.LoadAppConfig()
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "field 'secret' in cloud config must be a non-empty string")
	})

	t.Run("api_key with invalid structure", func(t *testing.T) {
		setupConfigFile(t, `{
			"cloud": {
				"id": "robot-id",
				"app_address": "https://app.viam.com",
				"api_key": "not-an-object"
			}
		}`)

		m := createTestManager(t)
		err := m.LoadAppConfig()
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, `"api_key" field is not a valid object`)
	})

	t.Run("api_key with missing id", func(t *testing.T) {
		setupConfigFile(t, `{
			"cloud": {
				"id": "robot-id",
				"app_address": "https://app.viam.com",
				"api_key": {
					"key": "api-key-secret"
				}
			}
		}`)

		m := createTestManager(t)
		err := m.LoadAppConfig()
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "field 'id' in 'api_key' must be a non-empty string")
	})

	t.Run("api_key with missing key", func(t *testing.T) {
		setupConfigFile(t, `{
			"cloud": {
				"id": "robot-id",
				"app_address": "https://app.viam.com",
				"api_key": {
					"id": "api-key-id"
				}
			}
		}`)

		m := createTestManager(t)
		err := m.LoadAppConfig()
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "field 'key' in 'api_key' must be a non-empty string")
	})
}

// TestSubsystemUpdatesViamServerRestart covers the viam-server restart block
// in SubsystemUpdates: the outer trigger (needRestart/configChange/agent/server
// flags), the RestartAllowed gate, Stop outcome handling, and the
// viamAgentNeedsRestart → Exit escape.
//
// Note on the viamServerNeedsRestart invariant: the flag tracks viam-server
// signals only (binary update or config change). Agent-only triggers
// (viamAgentNeedsRestart) never set it, even when Stop fails or RestartAllowed
// denies — those rows expect the flag to stay false.
func TestSubsystemUpdatesViamServerRestart(t *testing.T) {
	for _, tc := range []struct {
		name              string
		updateReturns     bool
		initialAgentFlag  bool
		restartNotAllowed bool
		stopErr           error

		wantStopCalls      int
		wantStartCalls     int
		wantViamServerFlag bool
		wantExitCalled     bool
	}{
		{
			name:           "no trigger; skip restart block",
			wantStopCalls:  0,
			wantStartCalls: 1,
		},
		{
			name:           "config change triggers; stop ok; flag cleared",
			updateReturns:  true,
			wantStopCalls:  1,
			wantStartCalls: 1,
		},
		{
			name:               "config change triggers; stop fails; flag set",
			updateReturns:      true,
			stopErr:            errors.New("stop failed"),
			wantStopCalls:      1,
			wantStartCalls:     1,
			wantViamServerFlag: true,
		},
		{
			name:               "config change triggers; restart not allowed; flag set, no stop",
			updateReturns:      true,
			restartNotAllowed:  true,
			wantStopCalls:      0,
			wantStartCalls:     1,
			wantViamServerFlag: true,
		},
		{
			name:             "agent restart pending; stop ok; exits without starting",
			initialAgentFlag: true,
			wantStopCalls:    1,
			wantStartCalls:   0,
			wantExitCalled:   true,
		},
		{
			name:             "agent restart pending; stop fails; exits anyway",
			initialAgentFlag: true,
			stopErr:          errors.New("stop failed"),
			wantStopCalls:    1,
			wantStartCalls:   0,
			wantExitCalled:   true,
		},
		{
			name:              "agent restart pending; restart not allowed; no exit",
			initialAgentFlag:  true,
			restartNotAllowed: true,
			wantStopCalls:     0,
			wantStartCalls:    1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			utils.MockAndCreateViamDirs(t)
			logger := logging.NewTestLogger(t)

			ctx, cancelCtx := context.WithCancel(context.Background())
			defer cancelCtx()

			var exitCalled bool
			globalCancel := func() {
				exitCalled = true
				cancelCtx()
			}

			cfg := utils.DefaultConfiguration
			fake := &fakeViamServer{
				updateFn:         func(context.Context, utils.AgentConfig) bool { return tc.updateReturns },
				stopFn:           func(context.Context) error { return tc.stopErr },
				restartAllowedFn: func(context.Context) bool { return !tc.restartNotAllowed },
			}
			m := &Manager{
				logger:                logger,
				cfg:                   cfg,
				globalCancel:          globalCancel,
				viamServer:            fake,
				networking:            networking.New(ctx, logger, cfg),
				cache:                 NewVersionCache(logger),
				agentStartTime:        time.Now(),
				viamAgentNeedsRestart: tc.initialAgentFlag,
			}
			m.sysConfig = syscfg.New(ctx, logger, cfg, m.GetNetAppender, false)

			m.SubsystemUpdates(ctx)

			test.That(t, fake.stopCalls, test.ShouldEqual, tc.wantStopCalls)
			test.That(t, fake.startCalls, test.ShouldEqual, tc.wantStartCalls)
			test.That(t, m.viamServerNeedsRestart, test.ShouldEqual, tc.wantViamServerFlag)
			test.That(t, exitCalled, test.ShouldEqual, tc.wantExitCalled)
		})
	}
}
