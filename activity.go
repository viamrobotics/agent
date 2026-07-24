package agent

import "sync/atomic"

// exitReason holds the first classified reason for this agent process's exit; it is
// attached to the shutdown activity events. The first reason recorded wins.
var exitReason atomic.Pointer[string]

// RecordExitReason stores reason unless one was already recorded.
func RecordExitReason(reason string) {
	exitReason.CompareAndSwap(nil, &reason)
}

// exitReasonOrDefault returns the recorded exit reason, or fallback if none was recorded.
func exitReasonOrDefault(fallback string) string {
	if r := exitReason.Load(); r != nil {
		return *r
	}
	return fallback
}
