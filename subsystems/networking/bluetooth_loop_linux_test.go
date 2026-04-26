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
			name:     "desired and off, no backoff gate",
			input:    bleDecisionInput{desiredRunning: true, currentState: bleOff, now: now, nextAttempt: past},
			expected: bleActionStart,
		},
		{
			name:     "desired and off, zero nextAttempt",
			input:    bleDecisionInput{desiredRunning: true, currentState: bleOff, now: now, nextAttempt: time.Time{}},
			expected: bleActionStart,
		},
		{
			name:     "desired and off, backoff gate holds",
			input:    bleDecisionInput{desiredRunning: true, currentState: bleOff, now: now, nextAttempt: future},
			expected: bleActionNone,
		},
		{
			name:     "desired and off, retries exhausted",
			input:    bleDecisionInput{desiredRunning: true, currentState: bleOff, now: now, nextAttempt: past, retriesExhausted: true},
			expected: bleActionNone,
		},
		{
			name:     "desired and starting",
			input:    bleDecisionInput{desiredRunning: true, currentState: bleStarting, now: now},
			expected: bleActionNone,
		},
		{
			name:     "desired and already running",
			input:    bleDecisionInput{desiredRunning: true, currentState: bleRunning, now: now},
			expected: bleActionNone,
		},
		{
			name:     "not desired and off",
			input:    bleDecisionInput{desiredRunning: false, currentState: bleOff, now: now},
			expected: bleActionNone,
		},
		{
			name:     "not desired and starting",
			input:    bleDecisionInput{desiredRunning: false, currentState: bleStarting, now: now},
			expected: bleActionStop,
		},
		{
			name:     "not desired and running",
			input:    bleDecisionInput{desiredRunning: false, currentState: bleRunning, now: now},
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
