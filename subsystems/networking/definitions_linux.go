package networking

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/viamrobotics/agent/utils"
	gnm "github.com/viamrobotics/gonetworkmanager/v2"
	pb "go.viam.com/api/provisioning/v1"
)

// This file contains type, const, and var definitions.

const (
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

	BTDiscoveryFilepath        = "/etc/bluetooth/viam-disable-reverse-discovery.conf"
	BTDiscoveryContentsDefault = "# This file intentionally left blank.\n"
	BTDiscoveryContentsDisable = "[General]\n# Explicitly disable\nReverseServiceDiscovery = false\n"
)

var (
	ErrBadPassword             = errors.New("bad or missing password")
	ErrConnCheckDisabled       = errors.New("NetworkManager connectivity checking disabled by user, network management will be unavailable")
	ErrNoActiveConnectionFound = errors.New("no active connection found")
	scanLoopDelay              = time.Second * 15
	scanTimeout                = time.Second * 30
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

// MachineConfig represents the minimal needed for /etc/viam.json.
type MachineConfig struct {
	Cloud *CloudConfig `json:"cloud"`
}

type CloudConfig struct {
	AppAddress string       `json:"app_address"`
	ID         string       `json:"id"`
	Secret     string       `json:"secret"`
	APIKey     utils.APIKey `json:"api_key,omitempty"`
}

func (cfg CloudConfig) IsValid() error {
	if cfg.ID == "" || cfg.AppAddress == "" {
		return errors.New("invalid cloud config: 'id' and 'app_address' must be provided")
	}
	if cfg.APIKey.IsPartiallySet() {
		return errors.New("invalid cloud config: 'api_key' is partially set, both 'id' and 'key' must be provided")
	}
	if cfg.Secret == "" && !cfg.APIKey.IsFullySet() {
		return errors.New("invalid cloud config: at least one of 'secret' or 'api_key' must be provided")
	}
	return nil
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
			APIKey:     input.APIKey,
		},
	}

	if err := cfg.Cloud.IsValid(); err != nil {
		return err
	}

	jsonBytes, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(file, jsonBytes, 0o600)
}

type userInputData struct {
	mu sync.Mutex

	inputChan chan<- userInput

	input   *userInput
	workers sync.WaitGroup

	// used to cancel background threads
	cancel context.CancelFunc

	connState *connectionState
}

// must be called with u.mu already locked!
func (u *userInputData) sendInput(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	select {
	case u.inputChan <- *u.input:
		u.connState.resetLastInteraction()
		u.input = &userInput{}
	case <-ctx.Done():
		u.connState.logger.Warn("user input not received by main loop after 60 seconds")
	}
}

func (u *userInputData) resetInputData(inputChan chan<- userInput) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.cancel != nil {
		u.cancel()
	}
	u.workers.Wait()
	u.cancel = nil
	u.input = &userInput{}
	u.inputChan = inputChan
}

type userInput struct {
	// network
	SSID string
	PSK  string

	// device credentials
	PartID  string
	Secret  string
	AppAddr string
	APIKey  utils.APIKey

	// raw /etc/viam.json contents
	RawConfig string
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

// NetKey is used to uniquely index connections. Use String() if a string representation is preferred.
type NetKey struct {
	// name is ssid for wifi or hotspot, otherwise just "wired" or "bluetooth"
	name string
	// ifname is the interface name, e.g. wlan0, eth0, or bluetooth hardware address
	ifname string
	// iftype is one of the NetworkType constants
	iftype string
}

var NetKeyUnknown = NetKey{
	name:   "UNKNOWN",
	ifname: "UNKNOWN",
	iftype: "UNKNOWN",
}

func (n NetKey) Type() string {
	if n == NetKeyUnknown {
		return ""
	}
	return n.iftype
}

func (n NetKey) Interface() string {
	if n == NetKeyUnknown {
		return ""
	}
	return n.ifname
}

func (n NetKey) Name() string {
	if n == NetKeyUnknown {
		return ""
	}
	return n.name
}

func (n NetKey) SSID() string {
	switch n.iftype {
	case NetworkTypeWired:
		return ""
	case NetworkTypeBluetooth:
		return ""
	default:
		// wifi or hotspot ssid
		return n.Name()
	}
}

// String returns a string representation of the NetKey.
// wifi is <ssid>@<ifname>, ex: "myNetwork@wlan0"
// wired is wired@<ifname>, ex: "wired@eth0"
// bluetooth is "bluetooth@<ifname>" where ifname is the hardware address of the remote device, ex: "bluetooth@1A:2B:3C:11:22:33".
func (n NetKey) String() string {
	if n.Name() == "" || n.Interface() == "" {
		return ""
	}
	return fmt.Sprintf("%s@%s", n.Name(), n.Interface())
}
