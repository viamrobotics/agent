package networking

import (
	"sync"
	"time"

	"go.viam.com/rdk/logging"
)

type provisioningMode struct {
	bluetoothActive bool
	hotspotActive   bool
}

type connectionState struct {
	mu sync.Mutex

	configured bool

	online     bool
	lastOnline time.Time

	connected     bool
	lastConnected time.Time

	provisioningMode   provisioningMode
	provisioningChange time.Time

	lastInteraction time.Time

	logger logging.Logger
}

func NewConnectionState(logger logging.Logger) *connectionState {
	return &connectionState{logger: logger}
}

func (c *connectionState) setOnline(online bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.online != online {
		c.logger.Infof("Online: %t", online)
	}

	c.online = online
	if online {
		c.lastOnline = time.Now()
	}
}

func (c *connectionState) getOnline() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.online
}

func (c *connectionState) getLastOnline() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastOnline
}

func (c *connectionState) setConnected(connected bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected != connected {
		c.logger.Infof("Wifi Connected: %t", connected)
	}

	c.connected = connected
	if connected {
		c.lastConnected = time.Now()
	}
}

func (c *connectionState) getConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

func (c *connectionState) getLastConnected() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastConnected
}

func (c *connectionState) setConfigured(configured bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.configured != configured {
		c.logger.Infof("Machine credentials present: %t", configured)
	}

	c.configured = configured
}

func (c *connectionState) getConfigured() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.configured
}

func (c *connectionState) setProvisioningBluetooth(isActive bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.provisioningMode.bluetoothActive = isActive
	c.provisioningChange = time.Now()
}

func (c *connectionState) setProvisioningHotspot(isActive bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.provisioningMode.hotspotActive = isActive
	c.provisioningChange = time.Now()
}

// getProvisioning returns true if in provisioning mode.
func (c *connectionState) getProvisioning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.provisioningMode.hotspotActive || c.provisioningMode.bluetoothActive
}

// getProvisioningHotspot returns true if the hotspot provisioning is active.
func (c *connectionState) getProvisioningHotspot() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.provisioningMode.hotspotActive
}

// getProvisioningBluetooth returns true if the bluetooth provisioning is active.
func (c *connectionState) getProvisioningBluetooth() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.provisioningMode.bluetoothActive
}

func (c *connectionState) getProvisioningChange() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.provisioningChange
}

func (c *connectionState) setLastInteraction() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastInteraction = time.Now()
}

func (c *connectionState) getLastInteraction() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastInteraction
}
