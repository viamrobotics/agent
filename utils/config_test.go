package utils

import (
	"encoding/json"
	"testing"

	"go.viam.com/test"
)

// SMURF TODO lots of tests

func TestConvertJson(t *testing.T) {
	jsonBytes := `
{
	"version_control": {
		"agent": "stable",
		"viam-server": "0.52.1"
	},
	"advanced_settings": {
		"debug": false,
		"wait_for_update_check": false,
		"viam_server_start_timeout_minutes": 10,
		"disable_viam_server": false,
		"disable_network_configuration": false,
		"disable_system_configuration": false
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
		"turn_on_hotspot_if_wifi_has_no_internet": false,
		"wifi_power_save": null
	},
	"additional_networks": {
		"network1": {
			"type": "",
			"interface": "",
			"ssid": "foo",
			"psk": "bar",
			"priority": 0,
			"ipv4_address": "",
			"ipv4_gateway": "",
			"ipv4_dns": [],
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
			"os_auto_upgrade_type": "security"
	}
}
`

	newConfig := &AgentConfig{}

	err := json.Unmarshal([]byte(jsonBytes), newConfig)

	test.That(t, err, test.ShouldBeNil)
	test.That(t, newConfig, test.ShouldResemble, &AgentConfig{})
}
