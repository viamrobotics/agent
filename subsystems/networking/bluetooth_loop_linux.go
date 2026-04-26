package networking

import (
	"context"
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
		if err := n.stopProvisioningBluetooth(); err != nil {
			n.logger.Warnw(
				"BLE reconciler failed to stop on shutdown",
				"event", "ble_reconcile_stop_failed",
				"err", err,
				"phase", "shutdown",
			)
		}
	}()

	tick := time.NewTicker(bleLoopTick)
	defer tick.Stop()

	n.logger.Info("bleLoop started")
	defer n.logger.Info("bleLoop stopped")

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

// logBleObservability emits BLE state transitions and a periodic status heartbeat
// so an operator can answer "what is BLE doing and why" from logs alone.
func (n *Subsystem) logBleObservability(s *bleLoopLogState) {
	now := time.Now()
	desired := n.bleDesired()
	state := n.ble.getState()
	backoffPending := n.bleBackoff > 0 && now.Before(n.bleNextAttempt)

	if !s.initialized {
		n.logger.Infow(
			"BLE reconciler initial state",
			"event", "ble_initial_state",
			"desired", desired,
			"state", state,
			"bluetooth_enabled", n.bluetoothEnabled(),
			"online", n.connState.getOnline(),
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
			"BLE desired state changed",
			"event", "ble_desired_changed",
			"desired", desired,
			"bluetooth_enabled", n.bluetoothEnabled(),
			"online", n.connState.getOnline(),
			"configured", n.connState.getConfigured(),
		)
		s.lastDesired = desired
	}

	if backoffPending && !s.lastBackoffPending {
		n.logger.Infow(
			"BLE start backed off, will retry",
			"event", "ble_backoff_pending",
			"backoff", n.bleBackoff,
			"next_attempt", n.bleNextAttempt,
		)
	}
	s.lastBackoffPending = backoffPending

	if now.Sub(s.lastStatusLog) >= bleStatusHeartbeat {
		n.logger.Infow(
			"BLE status",
			"event", "ble_status",
			"state", state,
			"desired", desired,
			"backoff_pending", backoffPending,
			"backoff_exhausted", n.bleBackoffExhausted(),
			"next_attempt", n.bleNextAttempt,
		)
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
			n.logger.Warnw(
				"BLE reconciler failed to start",
				"event", "ble_reconcile_start_failed",
				"err", err,
				"backoff", n.bleBackoff,
				"next_attempt", n.bleNextAttempt,
			)
			if n.bleBackoffExhausted() {
				n.logger.Warn("BLE startup keeps failing. If this device has no bluetooth hardware, " +
					"set disable_bt_provisioning to avoid these retries.")
			}
			return
		}
		n.bleBackoffReset()
		n.logger.Infow(
			"BLE reconciler started provisioning",
			"event", "ble_reconcile_started",
			"start_duration_ms", time.Since(startTime).Milliseconds(),
		)
	case bleActionStop:
		startTime := time.Now()
		if err := n.stopProvisioningBluetooth(); err != nil {
			n.logger.Warnw(
				"BLE reconciler failed to stop",
				"event", "ble_reconcile_stop_failed",
				"err", err,
			)
			return
		}
		n.logger.Infow(
			"BLE reconciler stopped provisioning",
			"event", "ble_reconcile_stopped",
			"stop_duration_ms", time.Since(startTime).Milliseconds(),
		)
	}
}

func (n *Subsystem) bleDesired() bool {
	if !n.bluetoothEnabled() {
		return false
	}
	if n.connState.getConfigured() && n.connState.getOnline() {
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
	isOnline := n.connState.getOnline()
	isConnected := n.connState.getConnected()
	hasConnectivity := isConnected || isOnline
	if n.Config().TurnOnHotspotIfWifiHasNoInternet.Get() {
		hasConnectivity = isOnline
	}
	isConfigured := n.connState.getConfigured()

	if err := n.btChar.updateStatus(isConfigured, hasConnectivity); err != nil {
		n.logger.Warnw("could not update BT status characteristic", "err", err)
	}
	if err := n.btChar.updateNetworks(n.cachedVisibleNetworks()); err != nil {
		n.logger.Warnw("could not update BT networks characteristic", "err", err)
	}
	if err := n.btChar.updateErrors(n.errListAsStrings()); err != nil {
		n.logger.Warnw("could not update BT errors characteristic", "err", err)
	}
}
