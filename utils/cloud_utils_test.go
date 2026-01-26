package utils

import (
	"testing"

	"go.viam.com/test"
)

func TestParseCloudCreds(t *testing.T) {
	t.Run("api_key authentication happy path", func(t *testing.T) {
		cloudCfg := map[string]any{
			"id":          "robot-id",
			"app_address": "https://app.viam.com",
			"api_key": map[string]any{
				"id":  "api-key-id",
				"key": "api-key-secret",
			},
		}

		creds, err := ParseCloudCreds(cloudCfg)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, creds, test.ShouldNotBeNil)
	})

	t.Run("api_key field is not a valid object", func(t *testing.T) {
		cloudCfg := map[string]any{
			"id":          "robot-id",
			"app_address": "https://app.viam.com",
			"api_key":     "not-an-object",
		}

		creds, err := ParseCloudCreds(cloudCfg)
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, `"api_key" field is not a valid object`)
		test.That(t, creds, test.ShouldBeNil)
	})

	t.Run("api_key with missing id field", func(t *testing.T) {
		cloudCfg := map[string]any{
			"id":          "robot-id",
			"app_address": "https://app.viam.com",
			"api_key": map[string]any{
				"key": "api-key-secret",
			},
		}

		creds, err := ParseCloudCreds(cloudCfg)
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "field 'id' in 'api_key' must be a non-empty string")
		test.That(t, creds, test.ShouldBeNil)
	})

	t.Run("api_key with empty id field", func(t *testing.T) {
		cloudCfg := map[string]any{
			"id":          "robot-id",
			"app_address": "https://app.viam.com",
			"api_key": map[string]any{
				"id":  "",
				"key": "api-key-secret",
			},
		}

		creds, err := ParseCloudCreds(cloudCfg)
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "field 'id' in 'api_key' must be a non-empty string")
		test.That(t, creds, test.ShouldBeNil)
	})

	t.Run("api_key with missing key field", func(t *testing.T) {
		cloudCfg := map[string]any{
			"id":          "robot-id",
			"app_address": "https://app.viam.com",
			"api_key": map[string]any{
				"id": "api-key-id",
			},
		}

		creds, err := ParseCloudCreds(cloudCfg)
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "field 'key' in 'api_key' must be a non-empty string")
		test.That(t, creds, test.ShouldBeNil)
	})

	t.Run("api_key with empty key field", func(t *testing.T) {
		cloudCfg := map[string]any{
			"id":          "robot-id",
			"app_address": "https://app.viam.com",
			"api_key": map[string]any{
				"id":  "api-key-id",
				"key": "",
			},
		}

		creds, err := ParseCloudCreds(cloudCfg)
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "field 'key' in 'api_key' must be a non-empty string")
		test.That(t, creds, test.ShouldBeNil)
	})

	t.Run("secret-based authentication happy path", func(t *testing.T) {
		cloudCfg := map[string]any{
			"id":          "robot-id",
			"app_address": "https://app.viam.com",
			"secret":      "robot-secret",
		}

		creds, err := ParseCloudCreds(cloudCfg)
		test.That(t, err, test.ShouldBeNil)
		test.That(t, creds, test.ShouldNotBeNil)
	})

	t.Run("secret-based auth with missing secret", func(t *testing.T) {
		cloudCfg := map[string]any{
			"id":          "robot-id",
			"app_address": "https://app.viam.com",
		}

		creds, err := ParseCloudCreds(cloudCfg)
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "field 'secret' in cloud config must be a non-empty string")
		test.That(t, creds, test.ShouldBeNil)
	})

	t.Run("secret-based auth with empty secret", func(t *testing.T) {
		cloudCfg := map[string]any{
			"id":          "robot-id",
			"app_address": "https://app.viam.com",
			"secret":      "",
		}

		creds, err := ParseCloudCreds(cloudCfg)
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "field 'secret' in cloud config must be a non-empty string")
		test.That(t, creds, test.ShouldBeNil)
	})

	t.Run("secret-based auth with missing id", func(t *testing.T) {
		cloudCfg := map[string]any{
			"app_address": "https://app.viam.com",
			"secret":      "robot-secret",
		}

		creds, err := ParseCloudCreds(cloudCfg)
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "field 'id' in cloud config must be a non-empty string")
		test.That(t, creds, test.ShouldBeNil)
	})

	t.Run("secret-based auth with empty id", func(t *testing.T) {
		cloudCfg := map[string]any{
			"id":          "",
			"app_address": "https://app.viam.com",
			"secret":      "robot-secret",
		}

		creds, err := ParseCloudCreds(cloudCfg)
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "field 'id' in cloud config must be a non-empty string")
		test.That(t, creds, test.ShouldBeNil)
	})

	t.Run("api_key takes priority over secret - does not fall back when api_key invalid", func(t *testing.T) {
		// Even though secret is valid, an invalid api_key causes an error rather than falling back to secret
		cloudCfg := map[string]any{
			"id":          "robot-id",
			"app_address": "https://app.viam.com",
			"secret":      "robot-secret",
			"api_key": map[string]any{
				"id": "api-key-id",
				// missing "key" field
			},
		}

		creds, err := ParseCloudCreds(cloudCfg)
		test.That(t, err, test.ShouldNotBeNil)
		test.That(t, err.Error(), test.ShouldContainSubstring, "field 'key' in 'api_key' must be a non-empty string")
		test.That(t, creds, test.ShouldBeNil)
	})
}

func TestAPIKey(t *testing.T) {
	t.Run("IsEmpty", func(t *testing.T) {
		test.That(t, APIKey{}.IsEmpty(), test.ShouldBeTrue)
		test.That(t, APIKey{ID: "id"}.IsEmpty(), test.ShouldBeFalse)
		test.That(t, APIKey{Key: "key"}.IsEmpty(), test.ShouldBeFalse)
		test.That(t, APIKey{ID: "id", Key: "key"}.IsEmpty(), test.ShouldBeFalse)
	})

	t.Run("IsFullySet", func(t *testing.T) {
		test.That(t, APIKey{}.IsFullySet(), test.ShouldBeFalse)
		test.That(t, APIKey{ID: "id"}.IsFullySet(), test.ShouldBeFalse)
		test.That(t, APIKey{Key: "key"}.IsFullySet(), test.ShouldBeFalse)
		test.That(t, APIKey{ID: "id", Key: "key"}.IsFullySet(), test.ShouldBeTrue)
	})

	t.Run("IsPartiallySet", func(t *testing.T) {
		test.That(t, APIKey{}.IsPartiallySet(), test.ShouldBeFalse)
		test.That(t, APIKey{ID: "id"}.IsPartiallySet(), test.ShouldBeTrue)
		test.That(t, APIKey{Key: "key"}.IsPartiallySet(), test.ShouldBeTrue)
		test.That(t, APIKey{ID: "id", Key: "key"}.IsPartiallySet(), test.ShouldBeFalse)
	})

	t.Run("APIKeyFromString", func(t *testing.T) {
		// Valid JSON with fully set key
		apiKey := APIKeyFromString(`{"id":"test-id","key":"test-key"}`)
		test.That(t, apiKey, test.ShouldNotBeNil)
		test.That(t, apiKey.ID, test.ShouldEqual, "test-id")
		test.That(t, apiKey.Key, test.ShouldEqual, "test-key")

		// Invalid JSON
		apiKey = APIKeyFromString(`invalid json`)
		test.That(t, apiKey, test.ShouldBeNil)

		// Valid JSON but partially set (missing key)
		apiKey = APIKeyFromString(`{"id":"test-id"}`)
		test.That(t, apiKey, test.ShouldBeNil)

		// Valid JSON but empty
		apiKey = APIKeyFromString(`{}`)
		test.That(t, apiKey, test.ShouldBeNil)

		// Empty string
		apiKey = APIKeyFromString(``)
		test.That(t, apiKey, test.ShouldBeNil)
	})
}
