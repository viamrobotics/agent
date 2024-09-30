package provisioning

import (
	"sync"

	gnm "github.com/Otterverse/gonetworkmanager/v2"
	"go.viam.com/rdk/logging"
)

type networkState struct {
	mu     sync.RWMutex
	logger logging.Logger

	// key is ssid@interface for wifi, ex: TestNetwork@wlan0
	// interface may be "any" for no interface set, ex: TestNetwork@any
	// wired networks are just interface, ex: eth0
	// generate with genNetKey(ifname, ssid)
	network map[string]*lockingNetwork

	// key is interface name, ex: wlan0
	primarySSID map[string]string
	activeSSID  map[string]string
	lastSSID    map[string]string
	activeConn  map[string]gnm.ActiveConnection
	ethDevice  map[string]gnm.DeviceWired
	wifiDevice map[string]gnm.DeviceWireless
}


func NewNetworkState(logger logging.Logger) *networkState {
	return &networkState{
		logger:      logger,
		network:     make(map[string]*lockingNetwork),
		activeSSID:  make(map[string]string),
		primarySSID: make(map[string]string),
		lastSSID:    make(map[string]string),
		ethDevice:   make(map[string]gnm.DeviceWired),
		wifiDevice:  make(map[string]gnm.DeviceWireless),
		activeConn:  make(map[string]gnm.ActiveConnection),
	}
}

// LockingNetwork returns a pointer to a network, wrapped in a lockable struct, so updates are persisted
// Users must lock the returned network before updates.
func (n *networkState) LockingNetwork(iface, ssid string) *lockingNetwork {
	n.mu.Lock()
	defer n.mu.Unlock()

	id := genNetKey(iface, ssid)

	net, ok := n.network[id]
	if !ok {
		n.logger.Debugf("cannot find existing network for %s, creating new", id)
		net := &lockingNetwork{}
		n.network[id] = net
		if ssid != "" {
			net.ssid = ssid
			net.netType = NetworkTypeWifi
		} else {
			net.netType = NetworkTypeWired
		}
		if iface != "any" || iface != "" {
			net.interfaceName = iface
		}
	}

	return net
}

// Network returns a copy-by-value of a network, which should be considered read-only, and doesn't need locking.
func (n *networkState) Network(iface, ssid string) network {
	net := n.LockingNetwork(iface, ssid)
	net.mu.Lock()
	defer net.mu.Unlock()
	return net.network
}

func (n *networkState) SetNetwork(iface, ssid string, net network) {
	ln := n.LockingNetwork(iface, ssid)
	ln.mu.Lock()
	ln.network = net
	ln.mu.Unlock()
}

func (n *networkState) LockingNetworks() []*lockingNetwork {
	n.mu.RLock()
	defer n.mu.RUnlock()

	nets := make([]*lockingNetwork, len(n.network))

	for _, net := range n.network {
		nets = append(nets, net)
	}

	return nets
}

func (n *networkState) Networks() []network {
	n.mu.RLock()
	defer n.mu.RUnlock()

	nets := make([]network, len(n.network))

	for _, net := range n.network {
		nets = append(nets, net.network)
	}

	return nets
}

func (n *networkState) LastNetwork(iface string) network {
	return n.Network(iface, n.LastSSID(iface))
}

func (n *networkState) PrimarySSID(iface string) string {
	n.mu.RLock()
	defer n.mu.RUnlock()

	ssid, ok := n.primarySSID[iface]
	if !ok {
		n.logger.Errorf("cannot find primary SSID for %s", iface)
		return ""
	}

	return ssid
}

func (n *networkState) SetPrimarySSID(iface, ssid string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if ssid == "" {
		delete(n.primarySSID, iface)
		return
	}
	n.primarySSID[iface] = ssid
}

func (n *networkState) ActiveSSID(iface string) string {
	n.mu.RLock()
	defer n.mu.RUnlock()

	ssid, ok := n.activeSSID[iface]
	if !ok {
		n.logger.Errorf("cannot find active SSID for %s", iface)
		return ""
	}

	return ssid
}

func (n *networkState) SetActiveSSID(iface, ssid string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if ssid == "" {
		delete(n.activeSSID, iface)
		return
	}
	n.activeSSID[iface] = ssid
}

func (n *networkState) LastSSID(iface string) string {
	n.mu.RLock()
	defer n.mu.RUnlock()

	ssid, ok := n.lastSSID[iface]
	if !ok {
		n.logger.Errorf("cannot find last SSID for %s", iface)
		return ""
	}

	return ssid
}

func (n *networkState) SetLastSSID(iface, ssid string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.lastSSID[iface] = ssid
}

func (n *networkState) ActiveConn(iface string) gnm.ActiveConnection {
	n.mu.RLock()
	defer n.mu.RUnlock()

	conn, ok := n.activeConn[iface]
	if !ok {
		n.logger.Errorf("cannot find active connection for %s", iface)
		return nil
	}

	return conn
}

func (n *networkState) SetActiveConn(iface string, conn gnm.ActiveConnection) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if conn == nil {
		delete(n.activeConn, iface)
		return
	}
	n.activeConn[iface] = conn
}

func (n *networkState) EthDevice(iface string) gnm.DeviceWired {
	n.mu.RLock()
	defer n.mu.RUnlock()

	dev, ok := n.ethDevice[iface]
	if !ok {
		n.logger.Errorf("cannot find eth device for %s", iface)
		return nil
	}

	return dev
}

func (n *networkState) SetEthDevice(iface string, dev gnm.DeviceWired) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.ethDevice[iface] = dev
}

func (n *networkState) WifiDevice(iface string) gnm.DeviceWireless {
	n.mu.RLock()
	defer n.mu.RUnlock()

	dev, ok := n.wifiDevice[iface]
	if !ok {
		n.logger.Errorf("cannot find wifi device for %s", iface)
		return nil
	}

	return dev
}

func (n *networkState) SetWifiDevice(iface string, dev gnm.DeviceWireless) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.wifiDevice[iface] = dev
}

func (n *networkState) Devices() map[string]gnm.Device {
 	n.mu.Lock()
	defer n.mu.Unlock()

	// merge the two device types into a single generic list
	allDevices := make(map[string]gnm.Device)
	for ifName, dev := range n.wifiDevice {
		allDevices[ifName] = dev
	}
	for ifName, dev := range n.ethDevice {
		allDevices[ifName] = dev
	}
	return allDevices
}
