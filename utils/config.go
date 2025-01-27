package utils

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	errw "github.com/pkg/errors"
	"github.com/tidwall/jsonc"
	pb "go.viam.com/api/app/agent/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

var (
	DefaultConfiguration = AgentConfig{
		AdvancedSettings{
			Debug:                         false,
			WaitForUpdateCheck:            false,
			DisableViamServer:             false,
			DisableNetworkConfiguration:   false,
			DisableSystemConfiguration:    false,
			ViamServerStartTimeoutMinutes: Timeout(time.Minute * 10),
		},
		SystemConfiguration{
			LoggingJournaldSystemMaxUseMegabytes:  512,
			LoggingJournaldRuntimeMaxUseMegabytes: 512,
			OSAutoUpgradeType:                     "",
		},
		NetworkConfiguration{
			Manufacturer:                        "viam",
			Model:                               "custom",
			FragmentID:                          "",
			HotspotInterface:                    "",
			HotspotPrefix:                       "viam-setup",
			HotspotPassword:                     "viamsetup",
			DisableCaptivePortalRedirect:        false,
			TurnOnHotspotIfWifiHasNoInternet:    false,
			WifiPowerSave:                       nil,
			OfflineBeforeStartingHotspotMinutes: Timeout(time.Minute * 2),
			UserIdleMinutes:                     Timeout(time.Minute * 5),
			RetryConnectionTimeoutMinutes:       Timeout(time.Minute * 10),
			DeviceRebootAfterOfflineMinutes:     Timeout(0),
			HotspotSSID:                         "",
		},
		AdditionalNetworks{},
	}

	configCacheFilename = "config_cache.json"

	// Can be overwritten via cli arguments.
	AppConfigFilePath     = "/etc/viam.json"
	DefaultsFilePath      = "/etc/viam-defaults.json"
	CLIDebug              = false
	CLIWaitForUpdateCheck = false
)

type AgentConfig struct {
	AdvancedSettings     AdvancedSettings     `json:"advanced_settings"`
	SystemConfiguration  SystemConfiguration  `json:"system_configuration"`
	NetworkConfiguration NetworkConfiguration `json:"network_configuration"`
	AdditionalNetworks   AdditionalNetworks   `json:"additional_networks"`
}

type AdvancedSettings struct {
	Debug                         bool    `json:"debug"`
	WaitForUpdateCheck            bool    `json:"wait_for_update_check"`
	DisableViamServer             bool    `json:"disable_viam_server"`
	DisableNetworkConfiguration   bool    `json:"disable_network_configuration"`
	DisableSystemConfiguration    bool    `json:"disable_system_configuration"`
	ViamServerStartTimeoutMinutes Timeout `json:"viam_server_start_timeout_minutes"`
}

type SystemConfiguration struct {
	// can set either to -1 to disable, defaults to 512M (when int is 0)
	LoggingJournaldSystemMaxUseMegabytes  int `json:"logging_journald_system_max_use_megabytes"`
	LoggingJournaldRuntimeMaxUseMegabytes int `json:"logging_journald_runtime_max_use_megabytes"`

	// UpgradeType can be
	// Empty/missing ("") to make no changes
	// "disable" (or "disabled") to disable auto-upgrades
	// "security" to enable ONLY security upgrades
	// "all" to enable upgrades from all configured sources
	OSAutoUpgradeType string `json:"os_auto_upgrade_type"`
}

type NetworkConfiguration struct {
	// Things typically set in viam-defaults.json
	Manufacturer string `json:"manufacturer"`
	Model        string `json:"model"`
	FragmentID   string `json:"fragment_id"`

	// The interface to use for hotspot/provisioning/wifi management. Ex: "wlan0"
	// Defaults to the first discovered 802.11 device
	HotspotInterface string `json:"hotspot_interface"`
	// The prefix to prepend to the hotspot name.
	HotspotPrefix string `json:"hotspot_prefix"`
	// Normally left blank, and computed from HotspotPrefix and Manufacturer
	HotspotSSID string `json:"hotspot_ssid"`
	// Password required to connect to the hotspot.
	HotspotPassword string `json:"hotspot_password"`
	// If true, mobile (phone) users connecting to the hotspot won't be automatically redirected to the web portal.
	DisableCaptivePortalRedirect bool `json:"disable_captive_portal_redirect"`

	// When true, will try all known networks looking for internet (global) connectivity.
	// Otherwise, will only try the primary wifi network and consider that sufficient if connected (regardless of global connectivity.)
	TurnOnHotspotIfWifiHasNoInternet bool `json:"turn_on_hotspot_if_wifi_has_no_internet"`

	// If set, will explicitly enable or disable power save for all wifi connections managed by NetworkManager.
	WifiPowerSave *bool `json:"wifi_power_save"`

	// How long without a connection before starting provisioning (hotspot) mode.
	OfflineBeforeStartingHotspotMinutes Timeout `json:"offline_before_starting_hotspot_minutes"`

	// How long since the last user interaction (via GRPC/app or web portal) before the state machine can resume.
	UserIdleMinutes Timeout `json:"user_idle_minutes"`

	// If not "online", always drop out of hotspot mode and retry everything after this time limit.
	RetryConnectionTimeoutMinutes Timeout `json:"retry_connection_timeout_minutes"`

	// If set, will reboot the device after it has been offline for this duration
	// 0, default, will disable this feature.
	DeviceRebootAfterOfflineMinutes Timeout `json:"device_reboot_after_offline_minutes"`
}

type AdditionalNetworks map[string]NetworkDefinition

type NetworkDefinition struct {
	// "wifi", "wired", "wifi-static", "wired-static"
	Type string `json:"type"`

	// name of interface, ex: "wlan0", "eth0", "enp14s0", etc.
	Interface string `json:"interface"`

	// Wifi Settings
	SSID string `json:"ssid"`
	PSK  string `json:"psk"`

	// Autoconnect Priority (primarily for wifi)
	// higher values are preferred/tried first
	// defaults to 0, but wifi networks added via hotspot are set to 999 when not in roaming mode
	Priority int32 `json:"priority"`

	// CIDR format address, ex: 192.168.0.1/24
	// If unset, will default to "auto" (dhcp)
	IPv4Address string `json:"ipv4_address"`
	IPv4Gateway string `json:"ipv4_gateway"`

	// optional
	IPv4DNS []string `json:"ipv4_dns"`

	// optional, 0 or -1 is default
	// lower values are preferred (lower "cost")
	// wired networks default to 100
	// wireless networks default to 600
	IPv4RouteMetric int64 `json:"ipv4_route_metric"`
}

func DefaultConfig() AgentConfig {
	cfg := AgentConfig{}
	// round-trip to get a deep copy of the default config
	defBytes, err := json.Marshal(DefaultConfiguration)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(defBytes, &cfg)
	if err != nil {
		panic(err)
	}
	return cfg
}

func SaveConfigToCache(cfg AgentConfig) error {
	cachePath := filepath.Join(ViamDirs["cache"], configCacheFilename)

	js, err := json.Marshal(cfg)
	if err != nil {
		return errw.Wrap(err, "marshalling config for caching")
	}

	_, err = WriteFileIfNew(cachePath, js)
	return errw.Wrapf(err, "writing config cache to %s", cachePath)
}

func LoadConfigFromCache() (AgentConfig, error) {
	cachePath := filepath.Join(ViamDirs["cache"], configCacheFilename)

	cfg := AgentConfig{}

	//nolint:gosec
	cacheBytes, err := os.ReadFile(cachePath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			cfg, newErr := StackConfigs(&pb.DeviceAgentConfigResponse{})
			return cfg, errors.Join(errw.Wrap(err, "reading config cache"), newErr)
		}
	} else {
		err = json.Unmarshal(cacheBytes, &cfg)
		if err != nil {
			cfg, newErr := StackConfigs(&pb.DeviceAgentConfigResponse{})
			return cfg, errors.Join(errw.Wrap(err, "parsing config cache"), newErr)
		}
	}

	return cfg, nil
}

func ApplyCLIArgs(cfg AgentConfig) AgentConfig {
	if CLIDebug {
		cfg.AdvancedSettings.Debug = true
	}
	if CLIWaitForUpdateCheck {
		cfg.AdvancedSettings.WaitForUpdateCheck = true
	}
	return cfg
}

func StackConfigs(proto *pb.DeviceAgentConfigResponse) (AgentConfig, error) {
	cfg := DefaultConfig()
	var errOut error

	// parse/apply deprecated /etc/viam-provisioning.json
	oldCfg, err := LoadOldProvisioningConfig()
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			errOut = errors.Join(errOut, errw.Wrap(err, "reading deprecated /etc/viam-provisioning.json"))
		}
	} else {
		cfg.NetworkConfiguration = *oldCfg
	}

	// manufacturer config from local disk (/etc/viam-defaults.json)
	jsonBytes, err := os.ReadFile(DefaultsFilePath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			errOut = errors.Join(errOut, err)
		}
	} else {
		if err := json.Unmarshal(jsonc.ToJSON(jsonBytes), &cfg); err != nil {
			errOut = errors.Join(errOut, err)
		}
	}

	// cloud-provided config
	cloudCfg, err := ProtoToConfig(proto)
	if err != nil {
		errOut = errors.Join(errOut, err)
	} else {
		jsonBytes, err = json.Marshal(cloudCfg)
		if err != nil {
			errOut = errors.Join(errOut, err)
		} else {
			if err := json.Unmarshal(jsonBytes, &cfg); err != nil {
				errOut = errors.Join(errOut, err)
			}
		}
	}

	// validate/enforce/limit values
	validatedCfg, err := validateConfig(cfg)
	errOut = errors.Join(errOut, err)

	return validatedCfg, errOut
}

// validateConfig enforces min/max values, returning a "corrected" config and error(s) for each issue encountered.
// Should only be called where input will NEVER be reused due to direct modification of struct fields.
func validateConfig(cfg AgentConfig) (AgentConfig, error) {
	var errOut error

	// AdvancedSettings
	if time.Duration(cfg.AdvancedSettings.ViamServerStartTimeoutMinutes) < time.Minute {
		errOut = errors.Join(errOut, errw.Errorf("agent.advanced_settings.viam_server_start_timeout_minutes must be >= 1m (was: %s)",
			time.Duration(cfg.AdvancedSettings.ViamServerStartTimeoutMinutes)))
		cfg.AdvancedSettings.ViamServerStartTimeoutMinutes = Timeout(time.Minute)
	}

	// SystemConfiguration
	// zero isn't allowed, revert to default, but don't warn
	if cfg.SystemConfiguration.LoggingJournaldSystemMaxUseMegabytes == 0 {
		//nolint:gofumpt
		cfg.SystemConfiguration.LoggingJournaldSystemMaxUseMegabytes =
			DefaultConfiguration.SystemConfiguration.LoggingJournaldSystemMaxUseMegabytes
	}
	if cfg.SystemConfiguration.LoggingJournaldRuntimeMaxUseMegabytes == 0 {
		//nolint:gofumpt
		cfg.SystemConfiguration.LoggingJournaldRuntimeMaxUseMegabytes =
			DefaultConfiguration.SystemConfiguration.LoggingJournaldRuntimeMaxUseMegabytes
	}
	if cfg.SystemConfiguration.OSAutoUpgradeType != "" &&
		cfg.SystemConfiguration.OSAutoUpgradeType != "security" &&
		cfg.SystemConfiguration.OSAutoUpgradeType != "all" {
		errOut = errors.Join(errOut, errw.Errorf(
			"agent.system_configuration.os_auto_upgrade_type can only be 'security' or 'all' (was: %s)",
			cfg.SystemConfiguration.OSAutoUpgradeType))
		cfg.SystemConfiguration.OSAutoUpgradeType = DefaultConfiguration.SystemConfiguration.OSAutoUpgradeType
	}

	// NetworkConfiguration
	if cfg.NetworkConfiguration.Manufacturer == "" {
		cfg.NetworkConfiguration.Manufacturer = DefaultConfiguration.NetworkConfiguration.Manufacturer
		errOut = errors.Join(errOut, errw.New("network_configuration.manufacturer should not be empty, please omit empty fields entirely"))
	}
	if cfg.NetworkConfiguration.Model == "" {
		cfg.NetworkConfiguration.Model = DefaultConfiguration.NetworkConfiguration.Model
		errOut = errors.Join(errOut, errw.New("network_configuration.model should not be empty, please omit empty fields entirely"))
	}
	if cfg.NetworkConfiguration.HotspotPrefix == "" {
		cfg.NetworkConfiguration.HotspotPrefix = DefaultConfiguration.NetworkConfiguration.HotspotPrefix
		errOut = errors.Join(errOut,
			errw.New("network_configuration.hotspot_prefix should not be empty, please omit empty fields entirely"))
	}
	if cfg.NetworkConfiguration.HotspotPassword == "" {
		cfg.NetworkConfiguration.HotspotPassword = DefaultConfiguration.NetworkConfiguration.HotspotPassword
		errOut = errors.Join(errOut,
			errw.New("network_configuration.hotspot_password should not be empty, please omit empty fields entirely"))
	}

	if cfg.NetworkConfiguration.HotspotSSID == "" {
		hostname, err := os.Hostname()
		if err != nil {
			errOut = errors.Join(errOut, errw.Wrap(err, "getting hostname"))
			hostname = "unknown"
		}
		cfg.NetworkConfiguration.HotspotSSID = cfg.NetworkConfiguration.HotspotPrefix + "-" + strings.ToLower(hostname)
	}
	if len(cfg.NetworkConfiguration.HotspotSSID) > 32 {
		cfg.NetworkConfiguration.HotspotSSID = cfg.NetworkConfiguration.HotspotSSID[:32]
		errOut = errors.Join(errOut, errw.New("network_configuration.hotspot_ssid is being truncated to 32 characters"))
	}

	var haveBadTimeout bool
	minTimeout := Timeout(time.Minute)
	if cfg.NetworkConfiguration.OfflineBeforeStartingHotspotMinutes < minTimeout {
		//nolint:gofumpt
		cfg.NetworkConfiguration.OfflineBeforeStartingHotspotMinutes =
			DefaultConfiguration.NetworkConfiguration.OfflineBeforeStartingHotspotMinutes
		haveBadTimeout = true
	}

	if cfg.NetworkConfiguration.UserIdleMinutes < minTimeout {
		cfg.NetworkConfiguration.UserIdleMinutes = DefaultConfiguration.NetworkConfiguration.UserIdleMinutes
		haveBadTimeout = true
	}

	if cfg.NetworkConfiguration.RetryConnectionTimeoutMinutes < minTimeout {
		//nolint:gofumpt
		cfg.NetworkConfiguration.RetryConnectionTimeoutMinutes =
			DefaultConfiguration.NetworkConfiguration.RetryConnectionTimeoutMinutes
		haveBadTimeout = true
	}

	if haveBadTimeout {
		errOut = errors.Join(errOut, errw.New("timeout values cannot be less than 1 minute"))
	}

	if cfg.NetworkConfiguration.DeviceRebootAfterOfflineMinutes != 0 &&
		(cfg.NetworkConfiguration.DeviceRebootAfterOfflineMinutes < cfg.NetworkConfiguration.OfflineBeforeStartingHotspotMinutes ||
			cfg.NetworkConfiguration.DeviceRebootAfterOfflineMinutes < cfg.NetworkConfiguration.UserIdleMinutes) {
		badOffline := cfg.NetworkConfiguration.DeviceRebootAfterOfflineMinutes
		cfg.NetworkConfiguration.DeviceRebootAfterOfflineMinutes = DefaultConfiguration.NetworkConfiguration.DeviceRebootAfterOfflineMinutes
		errOut = errors.Join(errOut,
			errw.Errorf("device_reboot_after_offline_minutes (%s) cannot be less than offline_before_starting_hotspot_minutes (%s) "+
				"or user_idle_minutes (%s)",
				time.Duration(badOffline),
				time.Duration(cfg.NetworkConfiguration.OfflineBeforeStartingHotspotMinutes),
				time.Duration(cfg.NetworkConfiguration.UserIdleMinutes)),
		)
	}

	// SMURF validate additional_networks
	return cfg, errOut
}

func ProtoToConfig(proto *pb.DeviceAgentConfigResponse) (AgentConfig, error) {
	var (
		conf        AgentConfig
		errOut, err error
	)

	conf.AdvancedSettings, err = ConvertStruct[AdvancedSettings](proto.GetAdvancedSettings())
	errOut = errors.Join(errOut, err)

	conf.SystemConfiguration, err = ConvertStruct[SystemConfiguration](proto.GetSystemConfiguration())
	errOut = errors.Join(errOut, err)

	conf.NetworkConfiguration, err = ConvertStruct[NetworkConfiguration](proto.GetNetworkConfiguration())
	errOut = errors.Join(errOut, err)

	conf.AdditionalNetworks, err = ConvertStruct[AdditionalNetworks](proto.GetAdditionalNetworks())
	errOut = errors.Join(errOut, err)

	return conf, errOut
}

func ConvertStruct[T any](proto *structpb.Struct) (T, error) {
	newConfig := new(T)

	jsonBytes, err := proto.MarshalJSON()
	if err != nil {
		return *newConfig, err
	}

	if err = json.Unmarshal(jsonBytes, newConfig); err != nil {
		return *newConfig, err
	}

	return *newConfig, nil
}

// Timeout allows parsing golang-style durations (1h20m30s) OR minutes-as-float from/to json.
type Timeout time.Duration

func (t Timeout) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(t).String())
}

func (t *Timeout) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case float64:
		*t = Timeout(value * float64(time.Minute))
		return nil
	case string:
		tmp, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		*t = Timeout(tmp)
		return nil
	default:
		return errw.Errorf("invalid duration: %+v", v)
	}
}
