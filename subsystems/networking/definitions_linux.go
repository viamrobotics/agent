package networking

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sync"
	"time"

	gnm "github.com/Otterverse/gonetworkmanager/v2"
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
