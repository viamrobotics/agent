package networking

import (
	"sync"
	"time"

	"go.viam.com/rdk/logging"
)

type provisioningMode int

const (
	none provisioningMode = iota
	hotspotOnly
	bluetoothOnly
	hotspotAndBluetooth
)

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

// getProvisioning returns true if in an active provisioning mode.
func (c *connectionState) getProvisioning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch c.provisioningMode {
	case none:
		return false
	case hotspotOnly, bluetoothOnly, hotspotAndBluetooth:
		return true
	}
	return false
}

// setProvisioningMode sets the provisioning mode
func (c *connectionState) setProvisioningMode(pm provisioningMode) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.provisioningMode = pm
	c.provisioningChange = time.Now()
}

// getProvisioningMode returns the provisioning mode.
func (c *connectionState) getProvisioningMode() provisioningMode {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.provisioningMode
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
