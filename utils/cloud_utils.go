// Package utils contains helper functions shared between the main agent and subsystems
package utils

import (
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

func ParseCloudCreds(cloudCfg map[string]interface{}) (rpc.DialOption, error) {
	if apiKeyInterface, hasApiKey := cloudCfg["api_key"]; hasApiKey {
		apiKey, ok := apiKeyInterface.(map[string]interface{})
		if !ok {
			return nil, errors.New(`"api_key" field is not a valid object`)
		}

		keyID, ok := apiKey["id"].(string)
		if !ok {
			return nil, errors.New(`no field for "id" in "api_key" or "id" is not a string`)
		}

		keySecret, ok := apiKey["key"].(string)
		if !ok {
			return nil, errors.New(`no field for "key" in "api_key" or "key" is not a string`)
		}
		creds := rpc.WithEntityCredentials(keyID, rpc.Credentials{rutils.CredentialsTypeAPIKey, keySecret})
		return creds, nil
	}

	// Fall back to secret-based auth
	secret, ok := cloudCfg["secret"].(string)
	if !ok {
		return nil, errors.New(`no cloud config field for "secret" or "api_key" or "secret" is not a string`)
	}

	id, ok := cloudCfg["id"].(string)
	if !ok {
		return nil, errors.New(`no cloud config field for "id" or "id" is not a string`)
	}
	creds := rpc.WithEntityCredentials(id, rpc.Credentials{rutils.CredentialsTypeRobotSecret, secret})
	return creds, nil
}
