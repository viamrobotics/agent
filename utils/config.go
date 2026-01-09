//nolint:goconst
package utils

import (
	"encoding/json"
	"errors"
	"io/fs"
	netlib "net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
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
			Debug:                         Tribool(0),
			WaitForUpdateCheck:            Tribool(0),
			DisableViamServer:             Tribool(0),
			DisableNetworkConfiguration:   Tribool(0),
			DisableSystemConfiguration:    Tribool(0),
			ViamServerStartTimeoutMinutes: Timeout(time.Minute * 10),
			ViamServerExtraEnvVars:        nil,
		},
		SystemConfiguration{
			LoggingJournaldSystemMaxUseMegabytes:  512,
			LoggingJournaldRuntimeMaxUseMegabytes: 512,
			ForwardSystemLogs:                     "",
			OSAutoUpgradeType:                     "",
		},
		NetworkConfiguration{
			Manufacturer:                        "viam",
			Model:                               "custom",
			FragmentID:                          "",
			HotspotInterface:                    "",
			HotspotPrefix:                       "viam-setup",
			HotspotPassword:                     "viamsetup",
			DisableCaptivePortalRedirect:        Tribool(0),
			TurnOnHotspotIfWifiHasNoInternet:    Tribool(0),
			WifiPowerSave:                       Tribool(0),
			OfflineBeforeStartingHotspotMinutes: Timeout(time.Minute * 2),
			UserIdleMinutes:                     Timeout(time.Minute * 5),
			RetryConnectionTimeoutMinutes:       Timeout(time.Minute * 10),
			DeviceRebootAfterOfflineMinutes:     Timeout(0),
			HotspotSSID:                         "",
			DisableBTProvisioning:               Tribool(0),
			DisableWifiProvisioning:             Tribool(0),
			BluetoothTrustAll:                   Tribool(0),
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

func init() {
	if runtime.GOOS == "windows" {
		DefaultConfiguration.AdvancedSettings.ViamServerStartTimeoutMinutes = Timeout(time.Minute)
	}
}

//nolint:recvcheck
type Tribool int

func (b Tribool) Get() bool {
	return b > 0
}

func (b Tribool) IsSet() bool {
	return b != 0
}

func (b Tribool) MarshalJSON() ([]byte, error) {
	if b == 1 {
		return []byte("true"), nil
	}
	return []byte("false"), nil
}

func (b *Tribool) UnmarshalJSON(data []byte) error {
	switch string(data) {
	case "true":
		*b = 1
	case "false":
		*b = -1
	default:
		*b = 0
	}
	return nil
}

type AgentConfig struct {
	AdvancedSettings     AdvancedSettings     `json:"advanced_settings,omitempty"`
	SystemConfiguration  SystemConfiguration  `json:"system_configuration,omitempty"`
	NetworkConfiguration NetworkConfiguration `json:"network_configuration,omitempty"`
	AdditionalNetworks   AdditionalNetworks   `json:"additional_networks,omitempty"`
}

type AdvancedSettings struct {
	Debug                         Tribool           `json:"debug,omitempty"`
	WaitForUpdateCheck            Tribool           `json:"wait_for_update_check,omitempty"`
	DisableViamServer             Tribool           `json:"disable_viam_server,omitempty"`
	DisableNetworkConfiguration   Tribool           `json:"disable_network_configuration,omitempty"`
	DisableSystemConfiguration    Tribool           `json:"disable_system_configuration,omitempty"`
	ViamServerStartTimeoutMinutes Timeout           `json:"viam_server_start_timeout_minutes,omitempty"`
	ViamServerExtraEnvVars        map[string]string `json:"viam_server_env,omitempty"`
}

// GetDisableNetworkConfiguration is a wrapper which force-disables on some OSes.
func (as AdvancedSettings) GetDisableNetworkConfiguration() bool {
	if runtime.GOOS == "windows" {
		return true
	}
	return as.DisableNetworkConfiguration.Get()
}

// GetDisableSystemConfiguration is a wrapper which force-disables on some OSes.
func (as AdvancedSettings) GetDisableSystemConfiguration() bool {
	if runtime.GOOS == "windows" {
		return true
	}
	return as.DisableSystemConfiguration.Get()
}

type SystemConfiguration struct {
	// can set either to -1 to disable, defaults to 512M (when int is 0)
	LoggingJournaldSystemMaxUseMegabytes  int `json:"logging_journald_system_max_use_megabytes,omitempty"`
	LoggingJournaldRuntimeMaxUseMegabytes int `json:"logging_journald_runtime_max_use_megabytes,omitempty"`

	// Enable forwarding of system logs (journald) to the cloud (disabled by default)
	// A comma-separated list of SYSLOG_IDENTIFIERs, optionally prefixed with "-" to exclude
	// "all" is a special keyword to log everything
	// Ex: "kernel,tailscaled,NetworkManager" or "all,-gdm,-tailscaled"
	ForwardSystemLogs string `json:"forward_system_logs,omitempty"`

	// UpgradeType can be
	// Empty/missing ("") to make no changes
	// "disable" (or "disabled") to disable auto-upgrades
	// "security" to enable ONLY security upgrades
	// "all" to enable upgrades from all configured sources
	OSAutoUpgradeType string `json:"os_auto_upgrade_type,omitempty"`
}

type NetworkConfiguration struct {
	// Things typically set in viam-defaults.json
	Manufacturer string `json:"manufacturer,omitempty"`
	Model        string `json:"model,omitempty"`
	FragmentID   string `json:"fragment_id,omitempty"`

	// The interface to use for hotspot/provisioning/wifi management. Ex: "wlan0"
	// Defaults to the first discovered 802.11 device
	HotspotInterface string `json:"hotspot_interface,omitempty"`
	// The prefix to prepend to the hotspot name.
	HotspotPrefix string `json:"hotspot_prefix,omitempty"`
	// Normally left blank, and computed from HotspotPrefix and Hostname
	HotspotSSID string `json:"hotspot_ssid,omitempty"`
	// Password required to connect to the hotspot.
	HotspotPassword string `json:"hotspot_password,omitempty"`
	// If true, mobile (phone) users connecting to the hotspot won't be automatically redirected to the web portal.
	DisableCaptivePortalRedirect Tribool `json:"disable_captive_portal_redirect,omitempty"`

	// When true, will try all known networks looking for internet (global) connectivity.
	// Otherwise, will only try the primary wifi network and consider that sufficient if connected (regardless of global connectivity.)
	TurnOnHotspotIfWifiHasNoInternet Tribool `json:"turn_on_hotspot_if_wifi_has_no_internet,omitempty"`

	// If set, will explicitly enable or disable power save for all wifi connections managed by NetworkManager.
	WifiPowerSave Tribool `json:"wifi_power_save,omitempty"`

	// How long without a connection before starting provisioning (hotspot) mode.
	OfflineBeforeStartingHotspotMinutes Timeout `json:"offline_before_starting_hotspot_minutes,omitempty"`

	// How long since the last user interaction (via GRPC/app or web portal) before the state machine can resume.
	UserIdleMinutes Timeout `json:"user_idle_minutes,omitempty"`

	// If not "online", always drop out of hotspot mode and retry everything after this time limit.
	RetryConnectionTimeoutMinutes Timeout `json:"retry_connection_timeout_minutes,omitempty"`

	// If set, will reboot the device after it has been offline for this duration
	// 0, default, will disable this feature.
	DeviceRebootAfterOfflineMinutes Timeout `json:"device_reboot_after_offline_minutes,omitempty"`

	// Disable flags for provisioning types.
	DisableBTProvisioning   Tribool `json:"disable_bt_provisioning,omitempty"`
	DisableWifiProvisioning Tribool `json:"disable_wifi_provisioning,omitempty"`

	// Accepts all BT pairing requests (for tethering) without requiring devices to be added via provisioning.
	BluetoothTrustAll Tribool `json:"bluetooth_trust_all,omitempty"`
}

type AdditionalNetworks map[string]NetworkDefinition

type NetworkDefinition struct {
	// "wifi", "wired", "bluetooth"
	Type string `json:"type,omitempty"`

	// name of interface, ex: "wlan0", "eth0", "enp14s0", etc.
	// for bluetooth tethering connections, uppercase hex, ex: "A1:B2:C3:11:22:3F"
	Interface string `json:"interface,omitempty"`

	// Wifi Settings
	SSID string `json:"ssid,omitempty"`
	PSK  string `json:"psk,omitempty"`

	// Autoconnect Priority (primarily for wifi)
	// higher values are preferred/tried first
	// defaults to 0, but wifi networks added via hotspot are set to 999 when not in roaming mode
	Priority int32 `json:"priority,omitempty"`

	// CIDR format address, ex: 192.168.0.1/24
	// If unset, will default to "auto" (dhcp)
	IPv4Address string `json:"ipv4_address,omitempty"`
	IPv4Gateway string `json:"ipv4_gateway,omitempty"`

	// optional
	IPv4DNS []string `json:"ipv4_dns,omitempty"`

	// optional, 0 or -1 is default
	// lower values are preferred (lower "cost")
	// wired networks default to 100
	// wireless networks default to 600
	IPv4RouteMetric int64 `json:"ipv4_route_metric,omitempty"`
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
	cachePath := filepath.Join(ViamDirs.Cache, configCacheFilename)

	js, err := json.Marshal(cfg)
	if err != nil {
		return errw.Wrap(err, "marshalling config for caching")
	}

	_, err = WriteFileIfNew(cachePath, js)
	return errw.Wrapf(err, "writing config cache to %s", cachePath)
}

func LoadConfigFromCache() (AgentConfig, error) {
	cachePath := filepath.Join(ViamDirs.Cache, configCacheFilename)

	cfg := AgentConfig{}

	//nolint:gosec
	cacheBytes, err := os.ReadFile(cachePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return StackOfflineConfig()
		} else {
			cfg, newErr := StackOfflineConfig()
			return cfg, errors.Join(errw.Wrap(err, "reading config cache"), newErr)
		}
	} else {
		err = json.Unmarshal(cacheBytes, &cfg)
		if err != nil {
			cfg, newErr := StackOfflineConfig()
			return cfg, errors.Join(errw.Wrap(err, "parsing config cache"), newErr)
		}
	}

	return validateConfig(cfg)
}

func ApplyCLIArgs(cfg AgentConfig) AgentConfig {
	if CLIDebug {
		cfg.AdvancedSettings.Debug = 1
	}
	if CLIWaitForUpdateCheck {
		cfg.AdvancedSettings.WaitForUpdateCheck = 1
	}
	return cfg
}

// StackOldProvisioningConfig reads viam-provisioning.json if available and merges it over startCfg.
func stackOldProvisioningConfig(startCfg AgentConfig) (AgentConfig, error) {
	var errOut error

	// parse/apply deprecated /etc/viam-provisioning.json (NetworkConfiguration only)
	oldCfg, err := LoadOldProvisioningConfig()
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			errOut = errors.Join(errOut, errw.Wrap(err, "reading deprecated /etc/viam-provisioning.json"))
		}
	} else {
		startCfg.NetworkConfiguration = *oldCfg
	}
	return startCfg, errOut
}

// StackOldProvisioningConfig reads viam-defaults.json if available and merges it over startCfg.
func stackViamDefaultsConfig(startCfg AgentConfig) (AgentConfig, error) {
	cfg := startCfg
	var errOut error

	// manufacturer config from local disk (/etc/viam-defaults.json)
	// use only if cloud read wasn't provided or unmarshall failed (don't merge the two).
	jsonBytes, err := os.ReadFile(DefaultsFilePath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			errOut = errors.Join(errOut, err)
		}
	} else {
		if err := json.Unmarshal(jsonc.ToJSON(jsonBytes), &cfg); err != nil {
			errOut = errors.Join(errOut, errw.Wrapf(err, "parsing %s", DefaultsFilePath))
		}
	}

	return cfg, errOut
}

// StackConfigs merges nextCfg over startCfg.
func StackConfigs(startCfg, nextCfg AgentConfig) (AgentConfig, error) {
	cfg := startCfg
	var errOut error

	jsonBytes, err := json.Marshal(nextCfg)
	if err != nil {
		errOut = errors.Join(errOut, err)
	} else {
		if err := json.Unmarshal(jsonBytes, &cfg); err != nil {
			errOut = errors.Join(errOut, err)
		}
	}
	return cfg, errOut
}

// StackOfflineConfig returns a merged config resulting from applying in order:
// DefaultConfig -> deprecated viam-provisioning.json -> viam-defaults.json.
func StackOfflineConfig() (AgentConfig, error) {
	return StackProtoConfig(nil)
}

// StackProtoConfig returns a merged config resulting from applying in order:
// DefaultConfig -> deprecated viam-provisioning.json -> cloud config if available & valid / otherwise viam-defaults.json.
func StackProtoConfig(fromCloudProto *pb.DeviceAgentConfigResponse) (AgentConfig, error) {
	cfg := DefaultConfig()
	var errOut error

	cfgTmp, err := stackOldProvisioningConfig(cfg)
	if err != nil {
		errOut = errors.Join(errOut, err)
	} else {
		cfg = cfgTmp
	}

	var cloudCfgSuccess bool
	if fromCloudProto != nil {
		cloudCfg, err := ProtoToConfig(fromCloudProto)
		if err != nil {
			errOut = errors.Join(errOut, err)
		} else {
			cfgTmp, err := StackConfigs(cfg, cloudCfg)
			if err != nil {
				errOut = errors.Join(errOut, err)
			} else {
				cfg = cfgTmp
				cloudCfgSuccess = true
			}
		}
	}

	// use viam-defaults (stack on top of base) only if cloud config is invalid
	if !cloudCfgSuccess {
		cfgTmp, err := stackViamDefaultsConfig(cfg)
		if err != nil {
			errOut = errors.Join(errOut, err)
		} else {
			cfg = cfgTmp
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
		//nolint:lll
		cfg.SystemConfiguration.LoggingJournaldSystemMaxUseMegabytes = DefaultConfiguration.SystemConfiguration.LoggingJournaldSystemMaxUseMegabytes
	}
	if cfg.SystemConfiguration.LoggingJournaldRuntimeMaxUseMegabytes == 0 {
		//nolint:lll
		cfg.SystemConfiguration.LoggingJournaldRuntimeMaxUseMegabytes = DefaultConfiguration.SystemConfiguration.LoggingJournaldRuntimeMaxUseMegabytes
	}
	if cfg.SystemConfiguration.OSAutoUpgradeType != "" &&
		cfg.SystemConfiguration.OSAutoUpgradeType != "security" &&
		cfg.SystemConfiguration.OSAutoUpgradeType != "all" &&
		cfg.SystemConfiguration.OSAutoUpgradeType != "disabled" &&
		cfg.SystemConfiguration.OSAutoUpgradeType != "disable" {
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

	if len(cfg.NetworkConfiguration.HotspotSSID) > 32 {
		errOut = errors.Join(errOut, errw.New("network_configuration.hotspot_ssid is being truncated to 32 characters"))
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
	}

	var haveBadTimeout bool
	minTimeout := Timeout(time.Minute)
	if cfg.NetworkConfiguration.OfflineBeforeStartingHotspotMinutes < minTimeout {
		//nolint:lll
		cfg.NetworkConfiguration.OfflineBeforeStartingHotspotMinutes = DefaultConfiguration.NetworkConfiguration.OfflineBeforeStartingHotspotMinutes
		haveBadTimeout = true
	}

	if cfg.NetworkConfiguration.UserIdleMinutes < minTimeout {
		cfg.NetworkConfiguration.UserIdleMinutes = DefaultConfiguration.NetworkConfiguration.UserIdleMinutes
		haveBadTimeout = true
	}

	if cfg.NetworkConfiguration.RetryConnectionTimeoutMinutes < minTimeout {
		cfg.NetworkConfiguration.RetryConnectionTimeoutMinutes = DefaultConfiguration.NetworkConfiguration.RetryConnectionTimeoutMinutes
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

	// Additional Networks
	for name, net := range cfg.AdditionalNetworks {
		if net.Type != "wifi" && net.Type != "wired" {
			errOut = errors.Join(errOut, errw.Errorf("network %s has invalid type (%s), must be one of "+
				"wifi or wired", name, net.Type))
			delete(cfg.AdditionalNetworks, name)
			continue
		}

		if len(net.Interface) > 15 || regexp.MustCompile(`\s`).MatchString(net.Interface) {
			errOut = errors.Join(errOut, errw.Errorf("network %s has invalid interface name (%s), "+
				"must be 15 characters or less, without spaces", name, net.Interface))
			delete(cfg.AdditionalNetworks, name)
			continue
		}

		if len(net.SSID) > 32 {
			errOut = errors.Join(errOut, errw.Errorf("network %s has invalid SSID (%s), "+
				"must be 32 characters or less", name, net.SSID))
			delete(cfg.AdditionalNetworks, name)
			continue
		}

		if len(net.PSK) > 64 || (net.PSK != "" && len(net.PSK) < 8) {
			errOut = errors.Join(errOut, errw.Errorf("network %s has invalid PSK (%s), "+
				"must be between 8 and 63 characters, or exactly 64 hex characters", name, net.PSK))
			delete(cfg.AdditionalNetworks, name)
			continue
		}

		if net.Priority > 999 || net.Priority < -999 {
			errOut = errors.Join(errOut, errw.Errorf("network %s has invalid priority (%d), "+
				"must be between -999 and 999", name, net.Priority))
			delete(cfg.AdditionalNetworks, name)
			continue
		}

		if net.IPv4Address != "" {
			_, _, err := netlib.ParseCIDR(net.IPv4Address)
			if err != nil {
				errOut = errors.Join(errOut, errw.Errorf("network %s has invalid ipv4_address, "+
					"%s", name, err))
				delete(cfg.AdditionalNetworks, name)
				continue
			}
		}

		if net.IPv4Gateway != "" {
			ip := netlib.ParseIP(net.IPv4Gateway)
			if ip == nil {
				errOut = errors.Join(errOut, errw.Errorf("network %s has invalid ipv4_gateway (%s), "+
					"must be ipv4 address", name, net.IPv4Gateway))
				delete(cfg.AdditionalNetworks, name)
				continue
			}
		}

		for _, dns := range net.IPv4DNS {
			ip := netlib.ParseIP(dns)
			if ip == nil {
				errOut = errors.Join(errOut, errw.Errorf("network %s has invalid ipv4_dns entry (%s), "+
					"must be ipv4 address", name, dns))
				delete(cfg.AdditionalNetworks, name)
				continue
			}
		}

		if net.IPv4RouteMetric < 0 {
			errOut = errors.Join(errOut, errw.Errorf("network %s has invalid ipv4_route_metric (%d), "+
				"must be >= 0", name, net.IPv4RouteMetric))
			delete(cfg.AdditionalNetworks, name)
			continue
		}
	}

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
		return errw.Errorf("invalid duration: %#v", v)
	}
}
