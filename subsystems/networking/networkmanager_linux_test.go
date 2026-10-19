package networking

import (
	"os"
	"path"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/viamrobotics/agent/utils"
	gnm "github.com/viamrobotics/gonetworkmanager/v2"
	"go.viam.com/rdk/logging"
	"go.viam.com/test"
)

type fakeActiveConn struct {
	gnm.ActiveConnection
	path     dbus.ObjectPath
	id       string
	state    gnm.NmActiveConnectionState
	settings gnm.ConnectionSettings
}

func (c *fakeActiveConn) GetPath() dbus.ObjectPath       { return c.path }
func (c *fakeActiveConn) GetPropertyID() (string, error) { return c.id, nil }
func (c *fakeActiveConn) GetPropertyState() (gnm.NmActiveConnectionState, error) {
	return c.state, nil
}

func (c *fakeActiveConn) GetPropertyConnection() (gnm.Connection, error) {
	return &fakeConnection{settings: c.settings}, nil
}

type fakeConnection struct {
	gnm.Connection
	settings gnm.ConnectionSettings
}

func (c *fakeConnection) GetSettings() (gnm.ConnectionSettings, error) { return c.settings, nil }

type fakeDevice struct {
	gnm.DeviceWired
	active gnm.ActiveConnection
}

func (d *fakeDevice) GetPropertyActiveConnection() (gnm.ActiveConnection, error) {
	return d.active, nil
}

type fakePrimaryNM struct {
	gnm.NetworkManager
	primary gnm.ActiveConnection
}

func (nm *fakePrimaryNM) GetPropertyPrimaryConnection() (gnm.ActiveConnection, error) {
	return nm.primary, nil
}

func TestLogActiveConnections(t *testing.T) {
	logger, logs := logging.NewObservedTestLogger(t)
	nm := &fakePrimaryNM{}
	n := &Subsystem{
		logger:   logger,
		nm:       nm,
		netState: NewNetworkState(logger),
		cfg:      utils.NetworkConfiguration{HotspotInterface: "wlan0", HotspotSSID: "viam-setup-test"},
	}
	activated := gnm.NmActiveConnectionStateActivated
	wifi := &fakeActiveConn{path: "/ac/1", id: "TestNetwork@wlan0", state: activated}
	eth := &fakeActiveConn{path: "/ac/2", id: "Wired connection 1", state: activated}
	setConn := func(ifName string, conn *fakeActiveConn, netType, ssid string) {
		if conn == nil {
			n.netState.ClearActive(ifName)
			return
		}
		n.netState.SetActiveConn(ifName, conn)
		n.netState.SetActiveType(ifName, netType)
		n.netState.SetActiveSSID(ifName, ssid)
		n.netState.SetActiveState(ifName, conn.state)
	}
	wifiEntry := activeConnLog{Interface: "wlan0", Type: NetworkTypeWifi, Name: "TestNetwork", State: "activated"}
	ethEntry := activeConnLog{Interface: "eth0", Type: NetworkTypeWired, Name: "Wired connection 1", State: "activated"}

	// drains the observer first, so every call returns only the fields of its own entry, or nil
	logged := func(t *testing.T) map[string]any {
		t.Helper()
		logs.TakeAll()
		n.logActiveConnections()
		entries := logs.FilterMessageSnippet("active network connections").All()
		if len(entries) == 0 {
			return nil
		}
		test.That(t, entries, test.ShouldHaveLength, 1)
		return entries[0].ContextMap()
	}

	t.Run("logs initial disconnected state", func(t *testing.T) {
		fields := logged(t)
		test.That(t, fields["connections"], test.ShouldBeEmpty)
		test.That(t, fields["primaryInterface"], test.ShouldEqual, "")
	})

	t.Run("stays quiet while unchanged", func(t *testing.T) {
		test.That(t, logged(t), test.ShouldBeNil)
	})

	t.Run("logs wifi on change", func(t *testing.T) {
		setConn("wlan0", wifi, NetworkTypeWifi, "TestNetwork")
		nm.primary = wifi
		fields := logged(t)
		test.That(t, fields["connections"], test.ShouldResemble, []activeConnLog{wifiEntry})
		test.That(t, fields["primaryInterface"], test.ShouldEqual, "wlan0")
		test.That(t, logged(t), test.ShouldBeNil)
	})

	t.Run("logs wired by connection id alongside wifi", func(t *testing.T) {
		setConn("eth0", eth, NetworkTypeWired, "")
		fields := logged(t)
		test.That(t, fields["connections"], test.ShouldResemble, []activeConnLog{ethEntry, wifiEntry})
		test.That(t, fields["primaryInterface"], test.ShouldEqual, "wlan0")
	})

	t.Run("logs activating connections and their state changes", func(t *testing.T) {
		badNet := &fakeActiveConn{path: "/ac/4", state: gnm.NmActiveConnectionStateActivating}
		setConn("wlan1", badNet, NetworkTypeWifi, "BadNet")
		badEntry := activeConnLog{Interface: "wlan1", Type: NetworkTypeWifi, Name: "BadNet", State: "activating"}
		test.That(t, logged(t)["connections"], test.ShouldResemble, []activeConnLog{ethEntry, wifiEntry, badEntry})
		test.That(t, logged(t), test.ShouldBeNil)

		n.netState.SetActiveState("wlan1", gnm.NmActiveConnectionStateActivated)
		badEntry.State = "activated"
		test.That(t, logged(t)["connections"], test.ShouldResemble, []activeConnLog{ethEntry, wifiEntry, badEntry})

		n.netState.SetActiveState("wlan1", gnm.NmActiveConnectionStateDeactivated)
		test.That(t, logged(t)["connections"], test.ShouldResemble, []activeConnLog{ethEntry, wifiEntry})
		setConn("wlan1", nil, "", "")
	})

	t.Run("logs primary change", func(t *testing.T) {
		nm.primary = eth
		fields := logged(t)
		test.That(t, fields["primaryInterface"], test.ShouldEqual, "eth0")
	})

	t.Run("leaves primary empty for an unknown connection", func(t *testing.T) {
		nm.primary = &fakeActiveConn{path: "/ac/vpn"}
		fields := logged(t)
		test.That(t, fields["primaryInterface"], test.ShouldEqual, "")
		nm.primary = eth
	})

	t.Run("relogs after the interval elapses", func(t *testing.T) {
		logged(t)
		n.loggedConnsTime = time.Now().Add(-activeConnLogInterval)
		test.That(t, logged(t), test.ShouldNotBeNil)
	})

	t.Run("logs disconnect", func(t *testing.T) {
		setConn("wlan0", nil, "", "")
		fields := logged(t)
		test.That(t, fields["connections"], test.ShouldResemble, []activeConnLog{ethEntry})
	})

	t.Run("logs hotspot by type", func(t *testing.T) {
		setConn("wlan0", &fakeActiveConn{path: "/ac/3", state: activated}, NetworkTypeHotspot, "viam-setup-test")
		fields := logged(t)
		test.That(t, fields["connections"], test.ShouldResemble, []activeConnLog{
			ethEntry, {Interface: "wlan0", Type: NetworkTypeHotspot, Name: "viam-setup-test", State: "activated"},
		})
		test.That(t, fields["primaryInterface"], test.ShouldEqual, "eth0")
	})
}

func TestCheckConnectionsClearsUnknownNetwork(t *testing.T) {
	logger := logging.NewTestLogger(t)
	n := &Subsystem{
		logger:    logger,
		netState:  NewNetworkState(logger),
		connState: NewConnectionState(logger),
		cfg:       utils.NetworkConfiguration{HotspotInterface: "wlan0"},
	}
	n.netState.SetActiveConn("eth0", &fakeActiveConn{path: "/ac/old"})
	n.netState.SetEthDevice("eth0", &fakeDevice{active: &fakeActiveConn{
		path:     "/ac/new",
		settings: gnm.ConnectionSettings{"connection": {"type": "pppoe"}},
	}})

	n.checkConnections()
	test.That(t, n.netState.ActiveConn("eth0"), test.ShouldBeNil)
}

func TestCheckForceProvisioning(t *testing.T) {
	// Mock ViamDirs to use temporary directory for testing
	utils.MockAndCreateViamDirs(t)

	tests := []struct {
		name                   string
		setupTouchFile         bool
		setupForceProvisioning time.Time
		retryTimeoutMinutes    int
		expectedResult         bool
	}{
		{
			name:                   "touch file exists - should trigger force provisioning",
			setupTouchFile:         true,
			setupForceProvisioning: time.Time{}, // zero time
			retryTimeoutMinutes:    10,
			expectedResult:         true,
		},
		{
			name:                   "touch file exists - force provisioning was set recently",
			setupTouchFile:         true,
			setupForceProvisioning: time.Now().Add(-time.Minute * 5), // 5 minutes ago
			retryTimeoutMinutes:    10,
			expectedResult:         true, // still within timeout
		},
		{
			name:                   "touch file exists - old force provisioning timeout expired",
			setupTouchFile:         true,
			setupForceProvisioning: time.Now().Add(-time.Minute * 15), // 15 minutes ago
			retryTimeoutMinutes:    10,
			expectedResult:         true, // touch file exists, so always returns true
		},
		{
			name:                   "no touch file - force provisioning not set",
			setupTouchFile:         false,
			setupForceProvisioning: time.Time{}, // zero time
			retryTimeoutMinutes:    10,
			expectedResult:         false,
		},
		{
			name:                   "no touch file - force provisioning was set recently",
			setupTouchFile:         false,
			setupForceProvisioning: time.Now().Add(-time.Minute * 5), // 5 minutes ago
			retryTimeoutMinutes:    10,
			expectedResult:         true, // still within timeout
		},
		{
			name:                   "no touch file - force provisioning timeout expired",
			setupTouchFile:         false,
			setupForceProvisioning: time.Now().Add(-time.Minute * 15), // 15 minutes ago
			retryTimeoutMinutes:    10,
			expectedResult:         false, // timeout expired
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a fresh networking instance for each test
			n := &Subsystem{
				logger: logging.NewTestLogger(t),
				connState: &connectionState{
					forceProvisioning: tt.setupForceProvisioning,
				},
				cfg: utils.NetworkConfiguration{
					RetryConnectionTimeoutMinutes: utils.Timeout(time.Duration(tt.retryTimeoutMinutes) * time.Minute),
				},
			}

			// Set up the touch file if needed
			touchFilePath := path.Join(utils.ViamDirs.Etc, "force_provisioning_mode")
			if tt.setupTouchFile {
				utils.Touch(t, touchFilePath)
			}

			// Call the function under test
			result := n.checkForceProvisioning()

			// Verify the result
			test.That(t, result, test.ShouldEqual, tt.expectedResult)

			// Verify the touch file was removed if it existed
			if tt.setupTouchFile {
				// Touch file should be removed after processing
				_, err := os.Stat(touchFilePath)
				test.That(t, err, test.ShouldNotBeNil)
				test.That(t, os.IsNotExist(err), test.ShouldBeTrue)
			}

			// Verify the force provisioning state
			if tt.setupTouchFile {
				// When touch file exists, force provisioning should be set to current time
				forceProvisioningTime := n.connState.getForceProvisioningTime()
				test.That(t, forceProvisioningTime.IsZero(), test.ShouldBeFalse)
				// Should be set to a recent time (within last 10 seconds)
				test.That(t, time.Since(forceProvisioningTime), test.ShouldBeLessThan, time.Second*10)
			} else {
				// When no touch file exists, force provisioning should remain unchanged
				forceProvisioningTime := n.connState.getForceProvisioningTime()
				if tt.setupForceProvisioning.IsZero() {
					test.That(t, forceProvisioningTime.IsZero(), test.ShouldBeTrue)
				} else {
					test.That(t, forceProvisioningTime, test.ShouldEqual, tt.setupForceProvisioning)
				}
			}
		})
	}
}
