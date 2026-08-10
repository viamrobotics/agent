package agent

import "sync/atomic"

// exitInfo holds the first classified reason for this agent process's exit, plus
// optional human-readable detail; both are attached to the shutdown activity events.
type exitInfo struct {
	reason string
	detail string
}

var recordedExit atomic.Pointer[exitInfo]

// RecordExitReason stores reason and optional human-readable detail unless a reason
// was already recorded. The first reason recorded wins.
func RecordExitReason(reason, detail string) {
	recordedExit.CompareAndSwap(nil, &exitInfo{reason: reason, detail: detail})
}

// exitReasonAndDetail returns the recorded exit reason and detail, or fallback and
// empty detail if none was recorded.
func exitReasonAndDetail(fallback string) (reason, detail string) {
	if i := recordedExit.Load(); i != nil {
		return i.reason, i.detail
	}
	return fallback, ""
}
