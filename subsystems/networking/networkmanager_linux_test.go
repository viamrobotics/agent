package networking

import (
	"os"
	"path"
	"testing"
	"time"

	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
	"go.viam.com/test"
)

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
			n := &Networking{
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
