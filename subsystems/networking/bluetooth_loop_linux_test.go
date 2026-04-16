package networking

import (
	"testing"
	"time"

	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
	"go.viam.com/test"
)

func TestDecideBleAction(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Minute)
	future := now.Add(time.Minute)

	tests := []struct {
		name     string
		input    bleDecisionInput
		expected bleAction
	}{
		{
			name:     "desired and off, no backoff gate",
			input:    bleDecisionInput{desired: true, currentState: bleOff, now: now, nextAttempt: past},
			expected: bleActionStart,
		},
		{
			name:     "desired and off, zero nextAttempt",
			input:    bleDecisionInput{desired: true, currentState: bleOff, now: now, nextAttempt: time.Time{}},
			expected: bleActionStart,
		},
		{
			name:     "desired and off, backoff gate holds",
			input:    bleDecisionInput{desired: true, currentState: bleOff, now: now, nextAttempt: future},
			expected: bleActionNone,
		},
		{
			name:     "desired and off, retries exhausted",
			input:    bleDecisionInput{desired: true, currentState: bleOff, now: now, nextAttempt: past, retriesExhausted: true},
			expected: bleActionNone,
		},
		{
			name:     "desired and starting",
			input:    bleDecisionInput{desired: true, currentState: bleStarting, now: now},
			expected: bleActionNone,
		},
		{
			name:     "desired and already running",
			input:    bleDecisionInput{desired: true, currentState: bleRunning, now: now},
			expected: bleActionNone,
		},
		{
			name:     "not desired and off",
			input:    bleDecisionInput{desired: false, currentState: bleOff, now: now},
			expected: bleActionNone,
		},
		{
			name:     "not desired and starting",
			input:    bleDecisionInput{desired: false, currentState: bleStarting, now: now},
			expected: bleActionStop,
		},
		{
			name:     "not desired and running",
			input:    bleDecisionInput{desired: false, currentState: bleRunning, now: now},
			expected: bleActionStop,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := decideBleAction(tt.input)
			test.That(t, result, test.ShouldEqual, tt.expected)
		})
	}
}

func TestBluetoothDesired(t *testing.T) {
	tests := []struct {
		name            string
		disableBT       utils.Tribool
		configured      bool
		online          bool
		expectedDesired bool
	}{
		{
			name:            "BT disabled",
			disableBT:       utils.Tribool(1),
			expectedDesired: false,
		},
		{
			name:            "not configured, not online",
			configured:      false,
			online:          false,
			expectedDesired: true,
		},
		{
			name:            "configured but not online",
			configured:      true,
			online:          false,
			expectedDesired: true,
		},
		{
			name:            "not configured but online",
			configured:      false,
			online:          true,
			expectedDesired: true,
		},
		{
			name:            "configured and online",
			configured:      true,
			online:          true,
			expectedDesired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logging.NewTestLogger(t)
			n := &Subsystem{
				logger:    logger,
				connState: NewConnectionState(logger),
				cfg: utils.NetworkConfiguration{
					DisableBTProvisioning: tt.disableBT,
				},
			}
			n.connState.setConfigured(tt.configured)
			n.connState.setOnline(tt.online)

			result := n.bluetoothDesired()
			test.That(t, result, test.ShouldEqual, tt.expectedDesired)
		})
	}
}

func TestBleBackoff(t *testing.T) {
	logger := logging.NewTestLogger(t)
	n := &Subsystem{
		logger:    logger,
		connState: NewConnectionState(logger),
	}

	t.Run("initial bump sets to 5s", func(t *testing.T) {
		n.bleBackoffReset()
		n.bleBackoffBump()
		test.That(t, n.bleBackoff, test.ShouldEqual, 5*time.Second)
		test.That(t, n.bleNextAttempt.IsZero(), test.ShouldBeFalse)
	})

	t.Run("repeated bumps double", func(t *testing.T) {
		n.bleBackoffReset()
		expected := []time.Duration{
			5 * time.Second,
			10 * time.Second,
			20 * time.Second,
			40 * time.Second,
			80 * time.Second,
			160 * time.Second,
			320 * time.Second,
		}
		for _, exp := range expected {
			n.bleBackoffBump()
			test.That(t, n.bleBackoff, test.ShouldEqual, exp)
		}
	})

	t.Run("caps at 10m", func(t *testing.T) {
		n.bleBackoffReset()
		for range 20 {
			n.bleBackoffBump()
		}
		test.That(t, n.bleBackoff, test.ShouldEqual, 10*time.Minute)
	})

	t.Run("reset returns to zero", func(t *testing.T) {
		n.bleBackoffBump()
		n.bleBackoffReset()
		test.That(t, n.bleBackoff, test.ShouldEqual, time.Duration(0))
		test.That(t, n.bleNextAttempt.IsZero(), test.ShouldBeTrue)
	})

	t.Run("after reset next bump starts from 5s", func(t *testing.T) {
		n.bleBackoffReset()
		for range 10 {
			n.bleBackoffBump()
		}
		n.bleBackoffReset()
		n.bleBackoffBump()
		test.That(t, n.bleBackoff, test.ShouldEqual, 5*time.Second)
	})

	t.Run("retriesExhausted is true at cap", func(t *testing.T) {
		n.bleBackoffReset()
		for range 20 {
			n.bleBackoffBump()
		}
		test.That(t, n.bleBackoff >= bleBackoffMax, test.ShouldBeTrue)
	})
}
