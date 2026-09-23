package networking

import (
	"os"
	"path"
	"testing"
	"time"

	"github.com/viamrobotics/agent/utils"
	"go.uber.org/zap/zaptest/observer"
	"go.viam.com/rdk/logging"
	"go.viam.com/test"
)

func TestLogActiveSSID(t *testing.T) {
	logger, logs := logging.NewObservedTestLogger(t)
	n := &Subsystem{
		logger:   logger,
		netState: NewNetworkState(logger),
		cfg:      utils.NetworkConfiguration{HotspotInterface: "wlan0"},
	}

	// drains the observer first, so every call below only sees its own entries
	logged := func(t *testing.T) []observer.LoggedEntry {
		t.Helper()
		logs.TakeAll()
		n.logActiveSSID()
		return logs.FilterMessageSnippet("active wifi network").All()
	}

	t.Run("logs initial disconnected state", func(t *testing.T) {
		entries := logged(t)
		test.That(t, entries, test.ShouldHaveLength, 1)
		test.That(t, entries[0].ContextMap()["activeSSID"], test.ShouldEqual, "")
		test.That(t, entries[0].ContextMap()["interface"], test.ShouldEqual, "wlan0")
	})

	t.Run("stays quiet while unchanged", func(t *testing.T) {
		test.That(t, logged(t), test.ShouldHaveLength, 0)
	})

	t.Run("logs immediately on change", func(t *testing.T) {
		n.netState.SetActiveSSID("wlan0", "TestNetwork")
		entries := logged(t)
		test.That(t, entries, test.ShouldHaveLength, 1)
		test.That(t, entries[0].ContextMap()["activeSSID"], test.ShouldEqual, "TestNetwork")
		test.That(t, logged(t), test.ShouldHaveLength, 0)
	})

	t.Run("ignores other interfaces", func(t *testing.T) {
		n.netState.SetActiveSSID("wlan1", "OtherNetwork")
		test.That(t, logged(t), test.ShouldHaveLength, 0)
	})

	t.Run("relogs after the interval elapses", func(t *testing.T) {
		n.loggedSSIDTime = time.Now().Add(-activeSSIDLogInterval)
		entries := logged(t)
		test.That(t, entries, test.ShouldHaveLength, 1)
		test.That(t, entries[0].ContextMap()["activeSSID"], test.ShouldEqual, "TestNetwork")
	})

	t.Run("logs disconnect", func(t *testing.T) {
		n.netState.SetActiveSSID("wlan0", "")
		entries := logged(t)
		test.That(t, entries, test.ShouldHaveLength, 1)
		test.That(t, entries[0].ContextMap()["activeSSID"], test.ShouldEqual, "")
	})
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
