package utils

import (
	"encoding/json"
	"os"
	"time"

	"github.com/tidwall/jsonc"
)

var (
	DefaultOldProvisioningConfig = OldProvisioningConfig{
		Manufacturer:                    "viam",
		Model:                           "custom",
		FragmentID:                      "",
		HotspotPrefix:                   "viam-setup",
		HotspotPassword:                 "viamsetup",
		DisableDNSRedirect:              false,
		RoamingMode:                     false,
		OfflineTimeout:                  Timeout(time.Minute * 2),
		UserTimeout:                     Timeout(time.Minute * 5),
		FallbackTimeout:                 Timeout(time.Minute * 10),
		WifiPowerSave:                   nil,
		DeviceRebootAfterOfflineMinutes: Timeout(0),
	}
	OldProvisioningConfigFilePath = "/etc/viam-provisioning.json"
)

// OldProvisioningConfig represents the json configurations parsed from either agent-provisioning.json.
type OldProvisioningConfig struct {
	// Things typically set in agent-provisioning.json
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	FragmentID   string `json:"fragment_id"`

	// The interface to use for hotspot/provisioning/wifi management. Ex: "wlan0"
	// Defaults to the first discovered 802.11 device
	HotspotInterface string `json:"hotspot_interface"`
	// The prefix to prepend to the hotspot name.
	HotspotPrefix string `json:"hotspot_prefix"`
	// Password required to connect to the hotspot.
	HotspotPassword string `json:"hotspot_password"`
	// If true, mobile (phone) users connecting to the hotspot won't be automatically redirected to the web portal.
	DisableDNSRedirect bool `json:"disable_dns_redirect"`

	// How long without a connection before starting provisioning (hotspot) mode.
	OfflineTimeout Timeout `json:"offline_timeout"`

	// How long since the last user interaction (via GRPC/app or web portal) before the state machine can resume.
	UserTimeout Timeout `json:"user_timeout"`

	// If not "online", always drop out of hotspot mode and retry everything after this time limit.
	FallbackTimeout Timeout `json:"fallback_timeout"`

	// When true, will try all known networks looking for internet (global) connectivity.
	// Otherwise, will only try the primary wifi network and consider that sufficient if connected (regardless of global connectivity.)
	RoamingMode bool `json:"roaming_mode"`

	// If set, will explicitly enable or disable power save for all wifi connections managed by NetworkManager.
	WifiPowerSave *bool `json:"wifi_power_save"`

	// If set, will reboot the device after it has been offline for this duration
	// 0, default, will disable this feature.
	DeviceRebootAfterOfflineMinutes Timeout `json:"device_reboot_after_offline_minutes"`
}

func LoadOldProvisioningConfig() (*NetworkConfiguration, error) {
	oldCfg := OldProvisioningConfig{}

	// round-trip to get a deep copy of the default config
	defBytes, err := json.Marshal(DefaultOldProvisioningConfig)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(defBytes, &oldCfg)
	if err != nil {
		panic(err)
	}

	// config from disk (/etc/viam-provisioning.json)
	jsonBytes, err := os.ReadFile(OldProvisioningConfigFilePath)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(jsonc.ToJSON(jsonBytes), &oldCfg); err != nil {
		return nil, err
	}

	return &NetworkConfiguration{
		Manufacturer:                        oldCfg.Manufacturer,
		Model:                               oldCfg.Model,
		FragmentID:                          oldCfg.FragmentID,
		HotspotInterface:                    oldCfg.HotspotInterface,
		HotspotPrefix:                       oldCfg.HotspotPrefix,
		HotspotPassword:                     oldCfg.HotspotPassword,
		DisableCaptivePortalRedirect:        oldCfg.DisableDNSRedirect,
		TurnOnHotspotIfWifiHasNoInternet:    oldCfg.RoamingMode,
		WifiPowerSave:                       oldCfg.WifiPowerSave,
		OfflineBeforeStartingHotspotMinutes: oldCfg.OfflineTimeout,
		UserIdleMinutes:                     oldCfg.UserTimeout,
		RetryConnectionTimeoutMinutes:       oldCfg.FallbackTimeout,
		DeviceRebootAfterOfflineMinutes:     oldCfg.DeviceRebootAfterOfflineMinutes,
	}, nil
}
