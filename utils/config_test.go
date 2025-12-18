package utils

import (
	"encoding/json"
	"testing"

	"go.viam.com/test"
)

// basic test for the config structure names.
func TestConvertJson(t *testing.T) {
	jsonBytes := `
{
	"version_control": {
		"agent": "stable",
		"viam-server": "0.52.1"
	},
	"advanced_settings": {
		"debug": false,
		"viam_server_start_timeout_minutes": 10
	},
	"network_configuration": {
		"manufacturer": "viam",
		"model": "custom",
		"fragment_id": "",
		"hotspot_prefix": "viam-setup",
		"hotspot_password": "viamsetup",
		"disable_captive_portal_redirect": false,
		"offline_before_starting_hotspot_minutes": 2,
		"user_idle_minutes": 5,
		"retry_connection_timeout_minutes": 10,
		"wifi_power_save": null,
		"bluetooth_trust_all": false
	},
	"additional_networks": {
		"network1": {
			"type": "wifi",
			"interface": "wlan0",
			"ssid": "foo",
			"psk": "bar",
			"priority": 0,
			"ipv4_address": "192.168.0.1/24",
			"ipv4_gateway": "192.168.0.255",
			"ipv4_dns": ["192.168.0.255"],
			"ipv4_route_metric": 0
		},
		"network2": {
			"ssid": "moo",
			"psk": "cow"
		}
	},
	"system_configuration": {
			"logging_journald_system_max_use_megabytes": 512,
			"logging_journald_runtime_max_use_megabytes": 512,
			"os_auto_upgrade_type": "",
			"forward_system_logs": ""
	}
}
`

	newConfig := &AgentConfig{}
	err := json.Unmarshal([]byte(jsonBytes), newConfig)

	testConfig := DefaultConfig()
	testConfig.AdditionalNetworks = map[string]NetworkDefinition{
		"network1": {
			Type:        "wifi",
			Interface:   "wlan0",
			SSID:        "foo",
			PSK:         "bar",
			IPv4Address: "192.168.0.1/24",
			IPv4Gateway: "192.168.0.255",
			IPv4DNS:     []string{"192.168.0.255"},
		},
		"network2": {
			SSID: "moo",
			PSK:  "cow",
		},
	}
	// these are explicitly false, rather than the "unset" for missing fields
	testConfig.AdvancedSettings.Debug = -1
	testConfig.NetworkConfiguration.DisableCaptivePortalRedirect = -1
	testConfig.NetworkConfiguration.BluetoothTrustAll = -1

	// these are explicitly true in the DefaultConfig, but we're testing unmarshalling of the above jsonBytes.
	testConfig.AdvancedSettings.DisableSystemConfiguration = 0
	testConfig.AdvancedSettings.DisableNetworkConfiguration = 0

	test.That(t, err, test.ShouldBeNil)
	test.That(t, *newConfig, test.ShouldResemble, testConfig)
}
