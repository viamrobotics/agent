package networking

import (
	"runtime"
	"sync"

	gnm "github.com/viamrobotics/gonetworkmanager/v2"
	"go.viam.com/rdk/logging"
)

type networkState struct {
	mu     sync.RWMutex
	logger logging.Logger

	// the wifi interface to default to when no interface is specified
	hotspotInterface string

	// these variables track and disable the scan-in-hotspot functionality
	scanFailCount   uint
	noScanInHotspot bool

	// key is ssid@interface for wifi, ex: TestNetwork@wlan0
	// interface may be "any" for no interface set, ex: TestNetwork@any
	// wired networks are just interface, ex: eth0
	// generate with GenNetKey(ifname, ssid)
	network map[NetKey]*lockingNetwork

	// key is interface name, ex: wlan0
	primarySSID map[string]string
	activeSSID  map[string]string
	lastSSID    map[string]string
	activeConn  map[string]gnm.ActiveConnection
	ethDevice   map[string]gnm.DeviceWired
	wifiDevice  map[string]gnm.DeviceWireless
	btDevice    map[string]gnm.Device
}

func NewNetworkState(logger logging.Logger) *networkState {
	return &networkState{
		logger:      logger,
		network:     make(map[NetKey]*lockingNetwork),
		activeSSID:  make(map[string]string),
		primarySSID: make(map[string]string),
		lastSSID:    make(map[string]string),
		ethDevice:   make(map[string]gnm.DeviceWired),
		wifiDevice:  make(map[string]gnm.DeviceWireless),
		btDevice:    make(map[string]gnm.Device),
		activeConn:  make(map[string]gnm.ActiveConnection),
	}
}

func (n *networkState) NoScanInHotspot() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.noScanInHotspot
}

func (n *networkState) SetNoScanInHotspot(noScan bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.noScanInHotspot = noScan
}

func (n *networkState) IncrementFailScan() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.scanFailCount++
	if n.scanFailCount >= 3 {
		n.noScanInHotspot = true
		n.logger.Warn("Device hardware/software does not appear to support wifi scanning while hotspot is active. " +
			"Further scanning will be disabled while in hotspot mode. Relying on fallback timeout to exit hotspot mode and allow rescans.")
	}
}

func (n *networkState) FailScan() uint {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.scanFailCount
}

func (n *networkState) ResetFailScan() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.scanFailCount = 0
}

func (n *networkState) SetHotspotInterface(iface string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.hotspotInterface = iface
}

// Users must lock the returned network before updates. Use Network() instead for a read-only copy.
func (n *networkState) LockingNetwork(id NetKey) *lockingNetwork {
	n.mu.Lock()
	defer n.mu.Unlock()

	net, ok := n.network[id]
	if !ok {
		net = &lockingNetwork{
			network: network{
				netType:       id.Type(),
				interfaceName: id.Interface(),
				ssid:          id.SSID(),
			},
		}
		n.network[id] = net
		n.logger.Debugf("found new network %s (%s)", id, net.netType)
	}

	return net
}

// Network returns a copy-by-value of a network, which should be considered read-only, and doesn't need locking.
func (n *networkState) Network(id NetKey) network {
	n.mu.Lock()
	defer n.mu.Unlock()
	ln, ok := n.network[id]
	if !ok {
		return network{}
	}
	ln.mu.Lock()
	defer ln.mu.Unlock()
	return ln.network
}

func (n *networkState) SetNetwork(id NetKey, net network) {
	ln := n.LockingNetwork(id)
	ln.mu.Lock()
	ln.network = net
	ln.mu.Unlock()
}

func (n *networkState) LockingNetworks() []*lockingNetwork {
	n.mu.RLock()
	defer n.mu.RUnlock()

	nets := []*lockingNetwork{}

	for _, net := range n.network {
		nets = append(nets, net)
	}

	return nets
}

func (n *networkState) Networks() []network {
	n.mu.RLock()
	defer n.mu.RUnlock()

	nets := []network{}

	for _, net := range n.network {
		nets = append(nets, net.network)
	}

	return nets
}

func (n *networkState) LastNetwork(netType, iface string) network {
	return n.Network(n.GenNetKey(netType, iface, n.LastSSID(iface)))
}

func (n *networkState) PrimarySSID(iface string) string {
	n.mu.RLock()
	defer n.mu.RUnlock()

	ssid, ok := n.primarySSID[iface]
	if !ok {
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
	return n.activeSSID[iface]
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
		n.logger.Warnf("cannot find eth device for %s", iface)
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
		n.logger.Warnf("cannot find wifi device for %s", iface)
		return nil
	}

	return dev
}

func (n *networkState) SetWifiDevice(iface string, dev gnm.DeviceWireless) {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.wifiDevice[iface] = dev
}

func (n *networkState) BTDevice(iface string) gnm.Device {
	n.mu.RLock()
	defer n.mu.RUnlock()

	dev, ok := n.btDevice[iface]
	if !ok {
		n.logger.Warnf("cannot find bluetooth device for %s", iface)
		return nil
	}

	return dev
}

func (n *networkState) SetBTDevice(iface string, dev gnm.Device) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.btDevice[iface] = dev
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
	for ifName, dev := range n.btDevice {
		allDevices[ifName] = dev
	}
	return allDevices
}

// GetNetworkDevice returns the appropriate network device for the given network type and interface.
func (n *networkState) GetNetworkDevice(netType, interfaceName string) gnm.Device {
	switch netType {
	case NetworkTypeWifi:
		return n.WifiDevice(interfaceName)
	case NetworkTypeHotspot:
		return n.WifiDevice(interfaceName)
	case NetworkTypeBluetooth:
		return n.BTDevice(interfaceName)
	case NetworkTypeWired:
		fallthrough
	default:
		// wired
		return n.EthDevice(interfaceName)
	}
}

// GenNetKey creates a unique, indexable string based on the type of network, interface, and ssid.
// If "ifName" is blank, and the type is wifi, it will use the hotspot interface (detected or set at runtime)
// as a default.
func (n *networkState) GenNetKey(netType, ifName, ssid string) NetKey {
	switch netType {
	case NetworkTypeHotspot:
		fallthrough
	case NetworkTypeWifi:
		if ifName == "" {
			n.mu.RLock()
			ifName = n.hotspotInterface
			n.mu.RUnlock()
		}
		return NetKey{ssid, ifName, NetworkTypeWifi}
	case NetworkTypeWired:
		return NetKey{NetworkTypeWired, ifName, NetworkTypeWired}
	case NetworkTypeBluetooth:
		return NetKey{NetworkTypeBluetooth, ifName, NetworkTypeBluetooth}
	default:
		n.logger.Warnf("encountered unknown network type: %s, interface: %s, ssid: %s", netType, ifName, ssid)
		_, file, no, ok := runtime.Caller(1)
		if ok {
			n.logger.Warnf("called from %s#%d", file, no)
		}
		return NetKeyUnknown
	}
}

// RemoveDevice removes a device from all device maps and cleans up associated state.
func (n *networkState) RemoveDevice(ifName string) {
	n.mu.Lock()
	defer n.mu.Unlock()

	// Remove from all device maps
	delete(n.wifiDevice, ifName)
	delete(n.ethDevice, ifName)
	delete(n.btDevice, ifName)

	// Clean up associated state
	delete(n.activeConn, ifName)
	delete(n.activeSSID, ifName)
	delete(n.lastSSID, ifName)
	delete(n.primarySSID, ifName)

	n.logger.Debugf("removed device %s from network state", ifName)
}
