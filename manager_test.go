package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
	"go.viam.com/test"
)

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
