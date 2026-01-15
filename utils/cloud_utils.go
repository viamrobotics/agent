// Package utils contains helper functions shared between the main agent and subsystems
package utils

import (
	"encoding/json"
	"errors"

	rutils "go.viam.com/rdk/utils"
	"go.viam.com/utils/rpc"
)

type APIKey struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

func (a APIKey) IsEmpty() bool {
	return a.ID == "" && a.Key == ""
}

func (a APIKey) IsFullySet() bool {
	return a.ID != "" && a.Key != ""
}

func (a APIKey) IsPartiallySet() bool {
	return !a.IsEmpty() && !a.IsFullySet()
}

func APIKeyFromString(value string) *APIKey {
	var apiKey APIKey
	if err := json.Unmarshal([]byte(value), &apiKey); err != nil || !apiKey.IsFullySet() {
		// If unmarshal fails or the result is not fully set, return empty APIKey. Empty APIKey won't be written to config.
		return nil
	}
	return &apiKey
}

func ParseCloudCreds(cloudCfg map[string]interface{}) (rpc.DialOption, error) {
	if apiKeyInterface, hasApiKey := cloudCfg["api_key"]; hasApiKey {
		apiKey, ok := apiKeyInterface.(map[string]interface{})
		if !ok {
			return nil, errors.New(`"api_key" field is not a valid object`)
		}

		keyID, ok := apiKey["id"].(string)
		if !ok || keyID == "" {
			return nil, errors.New("field 'id' in 'api_key' must be a non-empty string")
		}

		keySecret, ok := apiKey["key"].(string)
		if !ok || keySecret == "" {
			return nil, errors.New("field 'key' in 'api_key' must be a non-empty string")
		}
		creds := rpc.WithEntityCredentials(keyID, rpc.Credentials{rutils.CredentialsTypeAPIKey, keySecret})
		return creds, nil
	}

	// Fall back to secret-based auth
	secret, ok := cloudCfg["secret"].(string)
	if !ok || secret == "" {
		return nil, errors.New("field 'secret' in cloud config must be a non-empty string")
	}

	id, ok := cloudCfg["id"].(string)
	if !ok || id == "" {
		return nil, errors.New("field 'id' in cloud config must be a non-empty string")
	}
	creds := rpc.WithEntityCredentials(id, rpc.Credentials{rutils.CredentialsTypeRobotSecret, secret})
	return creds, nil
}
