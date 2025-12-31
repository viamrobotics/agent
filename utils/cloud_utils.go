// Package utils contains helper functions shared between the main agent and subsystems
package utils

import (
	"encoding/json"

	errw "github.com/pkg/errors"
	rutils "go.viam.com/rdk/utils"
	"go.viam.com/utils/rpc"
)

type APIKey struct {
	ID  string `json:"id"`
	Key string `json:"value"`
}

func (a APIKey) IsEmpty() bool {
	return a.ID == "" && a.Key == ""
}

func ParseCloudCreds(cloudCfg map[string]string) (rpc.DialOption, error) {
	// Check if api_key exists as a nested structure
	if apiKeyStr, hasApiKey := cloudCfg["api_key"]; hasApiKey {
		// Parse the api_key string as JSON into a map
		var apiKey map[string]string
		if err := json.Unmarshal([]byte(apiKeyStr), &apiKey); err != nil {
			return nil, errw.Wrap(err, `invalid JSON format for "api_key"`)
		}

		keyID, ok := apiKey["id"]
		if !ok {
			return nil, errw.Errorf(`no field for "id" in "api_key"`)
		}
		keySecret, ok := apiKey["key"]
		if !ok {
			return nil, errw.Errorf(`no field for "key" in "api_key"`)
		}
		creds := rpc.WithEntityCredentials(keyID, rpc.Credentials{rutils.CredentialsTypeAPIKey, keySecret})
		return creds, nil
	}

	// Fall back to secret-based auth
	secret, ok := cloudCfg["secret"]
	if !ok {
		return nil, errw.Errorf(`no cloud config field for "secret" or "api_key"`)
	}
	creds := rpc.WithEntityCredentials(cloudCfg["id"], rpc.Credentials{rutils.CredentialsTypeRobotSecret, secret})
	return creds, nil
}
