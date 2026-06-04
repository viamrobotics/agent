package networking

import (
	"testing"
	"time"

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
			name:     "should run, currently off, no backoff gate",
			input:    bleDecisionInput{shouldRun: true, currentState: bleOff, now: now, nextAttempt: past},
			expected: bleActionStart,
		},
		{
			name:     "should run, currently off, zero nextAttempt",
			input:    bleDecisionInput{shouldRun: true, currentState: bleOff, now: now, nextAttempt: time.Time{}},
			expected: bleActionStart,
		},
		{
			name:     "should run, currently off, backoff gate holds",
			input:    bleDecisionInput{shouldRun: true, currentState: bleOff, now: now, nextAttempt: future},
			expected: bleActionNone,
		},
		{
			name:     "should run, currently off, retries exhausted",
			input:    bleDecisionInput{shouldRun: true, currentState: bleOff, now: now, nextAttempt: past, retriesExhausted: true},
			expected: bleActionNone,
		},
		{
			name:     "should run, currently starting",
			input:    bleDecisionInput{shouldRun: true, currentState: bleStarting, now: now},
			expected: bleActionNone,
		},
		{
			name:     "should run, already running",
			input:    bleDecisionInput{shouldRun: true, currentState: bleRunning, now: now},
			expected: bleActionNone,
		},
		{
			name:     "should not run, currently off",
			input:    bleDecisionInput{shouldRun: false, currentState: bleOff, now: now},
			expected: bleActionNone,
		},
		{
			name:     "should not run, currently starting",
			input:    bleDecisionInput{shouldRun: false, currentState: bleStarting, now: now},
			expected: bleActionStop,
		},
		{
			name:     "should not run, currently running",
			input:    bleDecisionInput{shouldRun: false, currentState: bleRunning, now: now},
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

func TestShouldEnableBleFromState(t *testing.T) {
	tests := []struct {
		name       string
		enabled    bool
		configured bool
		online     bool
		connecting bool
		expected   bool
	}{
		{
			name:    "bluetooth disabled in config",
			enabled: false,
			// other fields irrelevant
			expected: false,
		},
		{
			name:       "connect attempt in progress suppresses BLE",
			enabled:    true,
			configured: false,
			online:     false,
			connecting: true,
			expected:   false,
		},
		{
			name:       "connect attempt overrides configured+online",
			enabled:    true,
			configured: true,
			online:     true,
			connecting: true,
			expected:   false,
		},
		{
			name:       "device online and configured, no attempt",
			enabled:    true,
			configured: true,
			online:     true,
			expected:   false,
		},
		{
			name:       "configured but offline, BLE wanted",
			enabled:    true,
			configured: true,
			online:     false,
			expected:   true,
		},
		{
			name:       "online but unconfigured, BLE wanted",
			enabled:    true,
			configured: false,
			online:     true,
			expected:   true,
		},
		{
			name:     "default unconfigured offline state, BLE wanted",
			enabled:  true,
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := shouldEnableBleFromState(tt.enabled, tt.configured, tt.online, tt.connecting)
			test.That(t, result, test.ShouldEqual, tt.expected)
		})
	}
}
