package networking

import (
	"context"
	"fmt"
	"time"

	"github.com/viamrobotics/agent/utils"
)

const (
	bleLoopTick        = time.Second
	bleStatusHeartbeat = time.Minute
)

// bleLoopLogState carries cross-tick observability state inside bleLoop.
type bleLoopLogState struct {
	initialized        bool
	lastDesired        bool
	lastBackoffPending bool
	lastStatusLog      time.Time
}

// bleLoop owns BLE lifecycle and characteristic updates. Single writer of all BLE state.
func (n *Subsystem) bleLoop(ctx context.Context) {
	defer utils.Recover(n.logger, nil)
	defer n.monitorWorkers.Done()
	defer func() {
		done := make(chan error, 1)
		go func() { done <- n.stopProvisioningBluetooth() }()
		select {
		case err := <-done:
			if err != nil {
				n.logger.Warnf("BLE failed to stop on shutdown: %v", err)
			}
		case <-time.After(10 * time.Second):
			n.logger.Warn("BLE stop on shutdown timed out after 10s; bluez may be unresponsive")
		}
	}()

	tick := time.NewTicker(bleLoopTick)
	defer tick.Stop()

	n.logger.Info("BLE provisioning monitor started")
	defer n.logger.Info("BLE provisioning monitor stopped")

	var logState bleLoopLogState
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			n.reconcileBle(ctx)
			n.logBleObservability(&logState)
			if n.ble.getState() == bleRunning {
				n.pushBleCharacteristics()
			}
		}
	}
}

// bleSummary returns a one-line, self-describing description of BLE state and
// the reason for it. Designed so the message remains useful even if a log viewer
// strips structured fields.
func (n *Subsystem) bleSummary(state bleState, desired, backoffPending bool) string {
	switch state {
	case bleRunning:
		return "BLE running"
	case bleStarting:
		return "BLE starting"
	case bleOff:
		// fall through
	default:
		return fmt.Sprintf("BLE in unknown state %s", state)
	}
	if !desired {
		switch {
		case !n.bluetoothEnabled():
			return "BLE off (bluetooth disabled in config)"
		case n.hasInternet() && n.connState.getConfigured():
			return "BLE off (device online and configured)"
		default:
			return "BLE off (not desired)"
		}
	}
	switch {
	case n.bleBackoffExhausted():
		return "BLE off (desired running but retries exhausted; if device has no bluetooth hardware, set disable_bt_provisioning)"
	case backoffPending:
		return "BLE off (desired running, waiting on backoff)"
	default:
		return "BLE off (desired running, will retry)"
	}
}

// logBleObservability emits BLE state transitions and a periodic status heartbeat
// so an operator can answer "what is BLE doing and why" from logs alone.
func (n *Subsystem) logBleObservability(s *bleLoopLogState) {
	now := time.Now()
	desired := n.bleDesired()
	state := n.ble.getState()
	backoffPending := n.bleBackoff > 0 && now.Before(n.bleNextAttempt)
	summary := n.bleSummary(state, desired, backoffPending)

	if !s.initialized {
		n.logger.Infow(
			"BLE provisioning monitor initial state: "+summary,
			"event", "ble_initial_state",
			"desired", desired,
			"state", state,
			"bluetooth_enabled", n.bluetoothEnabled(),
			"online", n.hasInternet(),
			"configured", n.connState.getConfigured(),
		)
		s.initialized = true
		s.lastDesired = desired
		s.lastBackoffPending = backoffPending
		s.lastStatusLog = now
		return
	}

	if desired != s.lastDesired {
		n.logger.Infow(
			"BLE desired state changed: "+summary,
			"event", "ble_desired_changed",
			"desired", desired,
			"bluetooth_enabled", n.bluetoothEnabled(),
			"online", n.hasInternet(),
			"configured", n.connState.getConfigured(),
		)
		s.lastDesired = desired
	}

	if backoffPending && !s.lastBackoffPending {
		n.logger.Infow(
			fmt.Sprintf("BLE start backed off, retrying in %s", n.bleBackoff),
			"event", "ble_backoff_pending",
			"backoff", n.bleBackoff,
			"next_attempt", n.bleNextAttempt,
		)
	}
	s.lastBackoffPending = backoffPending

	if now.Sub(s.lastStatusLog) >= bleStatusHeartbeat {
		msg := "BLE status: " + summary
		fields := []any{
			"event", "ble_status",
			"state", state,
			"desired", desired,
			"backoff_pending", backoffPending,
			"backoff_exhausted", n.bleBackoffExhausted(),
		}
		if !n.bleNextAttempt.IsZero() {
			fields = append(fields, "next_attempt", n.bleNextAttempt)
		}
		switch {
		case state == bleOff && !desired:
			// "BLE off because it isn't needed" is the steady state — keep noise low.
			n.logger.Debugw(msg, fields...)
		case state == bleOff && desired && n.bleBackoffExhausted():
			// BLE wanted but reconciler has given up — surface louder.
			n.logger.Warnw(msg, fields...)
		default:
			n.logger.Infow(msg, fields...)
		}
		s.lastStatusLog = now
	}
}

const (
	bleBackoffInitial = 5 * time.Second
	bleBackoffCap     = 20 * time.Minute
)

type bleAction int

const (
	bleActionNone bleAction = iota
	bleActionStart
	bleActionStop
)

type bleDecisionInput struct {
	desiredRunning   bool
	currentState     bleState
	now              time.Time
	nextAttempt      time.Time
	retriesExhausted bool
}

func decideBleAction(in bleDecisionInput) bleAction {
	switch {
	case in.desiredRunning && in.currentState == bleOff:
		if in.retriesExhausted || in.now.Before(in.nextAttempt) {
			return bleActionNone
		}
		return bleActionStart
	case !in.desiredRunning && in.currentState != bleOff:
		return bleActionStop
	default:
		return bleActionNone
	}
}

// reconcileBle converges BLE state toward the desired state. Called from bleLoop only.
func (n *Subsystem) reconcileBle(ctx context.Context) {
	action := decideBleAction(bleDecisionInput{
		desiredRunning:   n.bleDesired(),
		currentState:     n.ble.getState(),
		now:              time.Now(),
		nextAttempt:      n.bleNextAttempt,
		retriesExhausted: n.bleBackoffExhausted(),
	})
	switch action {
	case bleActionNone:
	case bleActionStart:
		startTime := time.Now()
		if err := n.startProvisioningBluetooth(ctx); err != nil {
			n.bleBackoffBump()
			n.logger.Warnf(
				"BLE start failed, next attempt at %s (in %s): %v",
				n.bleNextAttempt.Format(time.RFC3339), n.bleBackoff, err,
			)
			if n.bleBackoffExhausted() {
				n.logger.Warn("BLE startup keeps failing and retries are exhausted. " +
					"If this device has no bluetooth hardware, set disable_bt_provisioning to avoid these retries.")
			}
			return
		}
		n.bleBackoffReset()
		n.pushBleCharacteristics()
		elapsed := time.Since(startTime)
		n.logger.Infof("BLE provisioning started in %s", elapsed.Round(time.Millisecond))
	case bleActionStop:
		startTime := time.Now()
		if err := n.stopProvisioningBluetooth(); err != nil {
			n.logger.Warnf("BLE stop failed: %v", err)
			return
		}
		elapsed := time.Since(startTime)
		n.logger.Infof("BLE provisioning stopped in %s", elapsed.Round(time.Millisecond))
	}
}

func (n *Subsystem) bleDesired() bool {
	if !n.bluetoothEnabled() {
		return false
	}
	if n.connState.getConfigured() && n.hasInternet() {
		return false
	}
	return true
}

func (n *Subsystem) bleBackoffBump() {
	if n.bleBackoff == 0 {
		n.bleBackoff = bleBackoffInitial
	} else {
		n.bleBackoff *= 2
		if n.bleBackoff > bleBackoffCap {
			n.bleBackoff = bleBackoffCap
		}
	}
	n.bleNextAttempt = time.Now().Add(n.bleBackoff)
}

func (n *Subsystem) bleBackoffReset() {
	n.bleBackoff = 0
	n.bleNextAttempt = time.Time{}
}

// bleBackoffExhausted reports whether the backoff has reached its cap; reconciler stops retrying.
func (n *Subsystem) bleBackoffExhausted() bool {
	return n.bleBackoff >= bleBackoffCap
}

// pushBleCharacteristics writes fresh state into BLE characteristics.
func (n *Subsystem) pushBleCharacteristics() {
	if err := n.btChar.updateStatus(n.connState.getConfigured(), n.hasInternet()); err != nil {
		n.logger.Warnf("failed to refresh BLE status characteristic: %v", err)
	}
	if err := n.btChar.updateNetworks(n.cachedVisibleNetworks()); err != nil {
		n.logger.Warnf("failed to refresh BLE networks characteristic: %v", err)
	}
	if err := n.btChar.updateErrors(n.errListAsStrings()); err != nil {
		n.logger.Warnf("failed to refresh BLE errors characteristic: %v", err)
	}
}
