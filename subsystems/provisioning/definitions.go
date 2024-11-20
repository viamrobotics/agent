package provisioning

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"sync"
	"time"

	gnm "github.com/Otterverse/gonetworkmanager/v2"
	errw "github.com/pkg/errors"
	agentpb "go.viam.com/api/app/agent/v1"
	pb "go.viam.com/api/provisioning/v1"
)

// This file contains type, const, and var definitions.

const (
	SubsysName = "agent-provisioning"

	DNSMasqFilepath          = "/etc/NetworkManager/dnsmasq-shared.d/80-viam.conf"
	DNSMasqContentsRedirect  = "address=/#/10.42.0.1\n"
	DNSMasqContentsSetupOnly = "address=/.setup/10.42.0.1\n"

	PortalBindAddr = "10.42.0.1"

	ConnCheckFilepath = "/etc/NetworkManager/conf.d/80-viam.conf"
	ConnCheckContents = "[connectivity]\nuri=http://packages.viam.com/check_network_status.txt\ninterval=300\n"

	wifiPowerSaveFilepath        = "/etc/NetworkManager/conf.d/81-viam-wifi-powersave.conf"
	wifiPowerSaveContentsDefault = "# This file intentionally left blank.\n"
	wifiPowerSaveContentsDisable = "[connection]\n# Explicitly disable\nwifi.powersave = 2\n"
	wifiPowerSaveContentsEnable  = "[connection]\n# Explicitly enable\nwifi.powersave = 3\n"
	NetworkTypeWifi    = "wifi"
	NetworkTypeWired   = "wired"
	NetworkTypeHotspot = "hotspot"

	IfNameAny = "any"

	HealthCheckTimeout = time.Minute
)

var (
	DefaultConf = Config{
		Manufacturer:       "viam",
		Model:              "custom",
		FragmentID:         "",
		HotspotPrefix:      "viam-setup",
		HotspotPassword:    "viamsetup",
		DisableDNSRedirect: false,
		RoamingMode:        false,
		OfflineTimeout:     Timeout(time.Minute * 2),
		UserTimeout:        Timeout(time.Minute * 5),
		FallbackTimeout:    Timeout(time.Minute * 10),
		Networks:           []NetworkConfig{},
	}

	// Can be overwritten via cli arguments.
	AppConfigFilePath          = "/etc/viam.json"
	ProvisioningConfigFilePath = "/etc/viam-provisioning.json"

	ErrBadPassword             = errors.New("bad or missing password")
	ErrConnCheckDisabled       = errors.New("NetworkManager connectivity checking disabled by user, network management will be unavailable")
	ErrNoActiveConnectionFound = errors.New("no active connection found")
	scanLoopDelay              = time.Second * 15
	connectTimeout             = time.Second * 50 // longer than the 45 second timeout in NetworkManager
)

type lockingNetwork struct {
	mu sync.Mutex
	network
}

type network struct {
	netType   string
	ssid      string
	security  string
	signal    uint8
	priority  int32
	isHotspot bool

	firstSeen time.Time
	lastSeen  time.Time

	lastTried     time.Time
	connected     bool
	lastConnected time.Time
	lastError     error
	interfaceName string

	conn gnm.Connection
}

func (n *network) getInfo() NetworkInfo {
	var errStr string
	if n.lastError != nil {
		errStr = n.lastError.Error()
	}

	return NetworkInfo{
		Type:      n.netType,
		SSID:      n.ssid,
		Security:  n.security,
		Signal:    int32(n.signal),
		Connected: n.connected,
		LastError: errStr,
	}
}

type NetworkInfo struct {
	Type      string
	SSID      string
	Security  string
	Signal    int32
	Connected bool
	LastError string
}

func NetworkInfoToProto(net *NetworkInfo) *pb.NetworkInfo {
	return &pb.NetworkInfo{
		Type:      net.Type,
		Ssid:      net.SSID,
		Security:  net.Security,
		Signal:    net.Signal,
		Connected: net.Connected,
		LastError: net.LastError,
	}
}

func NetworkInfoFromProto(buf *pb.NetworkInfo) *NetworkInfo {
	return &NetworkInfo{
		Type:      buf.GetType(),
		SSID:      buf.GetSsid(),
		Security:  buf.GetSecurity(),
		Signal:    buf.GetSignal(),
		Connected: buf.GetConnected(),
		LastError: buf.GetLastError(),
	}
}

type NetworkConfig struct {
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

// MachineConfig represents the minimal needed for /etc/viam.json.
type MachineConfig struct {
	Cloud *CloudConfig `json:"cloud"`
}

type CloudConfig struct {
	AppAddress string `json:"app_address"`
	ID         string `json:"id"`
	Secret     string `json:"secret"`
}

func WriteDeviceConfig(file string, input userInput) error {
	if input.RawConfig != "" {
		return os.WriteFile(file, []byte(input.RawConfig), 0o600)
	}

	cfg := &MachineConfig{
		Cloud: &CloudConfig{
			AppAddress: input.AppAddr,
			ID:         input.PartID,
			Secret:     input.Secret,
		},
	}

	jsonBytes, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(file, jsonBytes, 0o600)
}

type portalData struct {
	mu      sync.Mutex
	Updated time.Time

	inputChan chan<- userInput

	input   *userInput
	workers sync.WaitGroup

	// used to cancel background threads
	cancel context.CancelFunc
}

// must be called with p.mu already locked!
func (p *portalData) sendInput(connState *connectionState) {
	input := *p.input

	// in case both network and device credentials are being updated
	// only send user data if both are already set
	if (input.SSID != "" && input.PartID != "") ||
		(input.SSID != "" && connState.getConfigured()) ||
		(input.PartID != "" && connState.getOnline()) {
		p.input = &userInput{}
		p.inputChan <- input
		if p.cancel != nil {
			p.cancel()
		}
		return
	}
	// if not, wait 10 seconds for full input
	if p.cancel != nil {
		p.cancel()
	}

	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel

	p.workers.Add(1)
	go func() {
		defer p.workers.Done()
		p.mu.Lock()
		defer p.mu.Unlock()
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second * 10):
		}
		p.input = &userInput{}
		p.inputChan <- input
	}()
}

type userInput struct {
	// network
	SSID string
	PSK  string

	// device credentials
	PartID  string
	Secret  string
	AppAddr string

	// raw /etc/viam.json contents
	RawConfig string
}

func ConfigFromJSON(defaultConf Config, jsonBytes []byte) (*Config, error) {
	minTimeout := Timeout(time.Second * 15)
	conf := defaultConf
	if err := json.Unmarshal(jsonBytes, &conf); err != nil {
		return &defaultConf, err
	}

	if conf.Manufacturer == "" || conf.Model == "" || conf.HotspotPrefix == "" || conf.HotspotPassword == "" {
		return &defaultConf, errw.New("values in configs/attributes should not be empty, please omit empty fields entirely")
	}

	var haveBadTimeout bool
	if conf.OfflineTimeout < minTimeout {
		conf.OfflineTimeout = defaultConf.OfflineTimeout
		haveBadTimeout = true
	}

	if conf.UserTimeout < minTimeout {
		conf.UserTimeout = defaultConf.UserTimeout
		haveBadTimeout = true
	}

	if conf.FallbackTimeout < minTimeout {
		conf.FallbackTimeout = defaultConf.FallbackTimeout
		haveBadTimeout = true
	}

	if haveBadTimeout {
		return &conf, errw.Errorf("timeout values cannot be less than %s", time.Duration(minTimeout))
	}

	return &conf, nil
}

func LoadConfig(updateConf *agentpb.DeviceSubsystemConfig) (*Config, error) {
	newCfg := DefaultConf
	cfg := &newCfg

	// config from disk (/etc/viam-provisioning.json)
	jsonBytes, err := os.ReadFile(ProvisioningConfigFilePath)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	if err == nil {
		cfg, err = ConfigFromJSON(DefaultConf, jsonBytes)
		if err != nil {
			return cfg, errw.Wrap(err, "parsing viam-provisioning.json")
		}
	}

	// update with config from cloud (subsys attributes)
	jsonBytes, err = updateConf.GetAttributes().MarshalJSON()
	if err != nil {
		return cfg, errw.Wrap(err, "marshaling JSON from attributes")
	}

	cfg, err = ConfigFromJSON(*cfg, jsonBytes)
	if err != nil {
		return cfg, errw.Wrap(err, "parsing JSON from attributes")
	}

	return cfg, nil
}

// Config represents the json configurations parsed from either agent-provisioning.json OR passed from the "attributes" in the cloud config.
type Config struct {
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

	// Additional networks to add/configure. Only useful in RoamingMode.
	Networks []NetworkConfig `json:"networks"`

	// Computed from HotspotPrefix and Manufacturer
	hotspotSSID string

	// If set, will explicitly enable or disable power save for all wifi connections managed by NetworkManager.
	WifiPowerSave *bool `json:"wifi_power_save"`
}

// Timeout allows parsing golang-style durations (1h20m30s) OR seconds-as-float from/to json.
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
		*t = Timeout(value * float64(time.Second))
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

type health struct {
	mu   sync.Mutex
	last time.Time
}

func (h *health) MarkGood() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.last = time.Now()
}

func (h *health) Sleep(ctx context.Context, timeout time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(timeout):
		h.mu.Lock()
		defer h.mu.Unlock()
		h.last = time.Now()
		return true
	}
}

func (h *health) IsHealthy() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return time.Since(h.last) < HealthCheckTimeout
}

type errorList struct {
	mu     sync.Mutex
	errors []error
}

func (e *errorList) Add(err ...error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.errors = append(e.errors, err...)
}

func (e *errorList) Clear() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.errors = []error{}
}

func (e *errorList) Errors() []error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.errors
}

type banner struct {
	mu     sync.Mutex
	banner string
}

func (b *banner) Set(banner string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.banner = banner
}

func (b *banner) Get() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.banner
}
