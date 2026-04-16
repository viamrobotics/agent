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
