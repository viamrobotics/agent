package networking

import (
	"context"
	"time"

	"github.com/viamrobotics/agent/utils"
)

const bleLoopTick = time.Second

// bleLoop owns BLE lifecycle and characteristic updates. Single writer of all BLE state.
func (n *Subsystem) bleLoop(ctx context.Context) {
	defer utils.Recover(n.logger, nil)
	defer n.monitorWorkers.Done()
	defer func() {
		if err := n.stopProvisioningBluetooth(); err != nil {
			n.logger.Warnw(
				"ble_reconcile_stop_failed",
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

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			n.reconcileBluetooth(ctx)
			if n.getBleState() == bleRunning {
				n.pushBluetoothCharacteristics()
			}
		}
	}
}

const (
	bleBackoffInitial = 5 * time.Second
	bleBackoffMax     = 10 * time.Minute
)

type bleAction int

const (
	bleActionNone bleAction = iota
	bleActionStart
	bleActionStop
)

type bleDecisionInput struct {
	desired          bool
	currentState     bleState
	now              time.Time
	nextAttempt      time.Time
	retriesExhausted bool
}

func decideBleAction(in bleDecisionInput) bleAction {
	switch {
	case in.desired && in.currentState == bleOff:
		if in.retriesExhausted || in.now.Before(in.nextAttempt) {
			return bleActionNone
		}
		return bleActionStart
	case !in.desired && in.currentState != bleOff:
		return bleActionStop
	default:
		return bleActionNone
	}
}

// reconcileBluetooth converges BLE state toward the desired state. Called from bleLoop only.
func (n *Subsystem) reconcileBluetooth(ctx context.Context) {
	action := decideBleAction(bleDecisionInput{
		desired:          n.bluetoothDesired(),
		currentState:     n.getBleState(),
		now:              time.Now(),
		nextAttempt:      n.bleNextAttempt,
		retriesExhausted: n.bleBackoff >= bleBackoffMax,
	})
	switch action {
	case bleActionNone:
	case bleActionStart:
		started := time.Now()
		if err := n.startProvisioningBluetooth(ctx); err != nil {
			n.bleBackoffBump()
			n.logger.Warnw(
				"ble_reconcile_start_failed",
				"event", "ble_reconcile_start_failed",
				"err", err,
				"backoff", n.bleBackoff,
				"next_attempt", n.bleNextAttempt,
			)
			if n.bleBackoff >= bleBackoffMax {
				n.logger.Warn("BLE startup keeps failing. If this device has no bluetooth hardware, " +
					"set disable_bt_provisioning to avoid these retries.")
			}
			return
		}
		n.bleBackoffReset()
		n.logger.Infow(
			"ble_reconcile_started",
			"event", "ble_reconcile_started",
			"duration_ms", time.Since(started).Milliseconds(),
		)
	case bleActionStop:
		started := time.Now()
		if err := n.stopProvisioningBluetooth(); err != nil {
			n.logger.Warnw(
				"ble_reconcile_stop_failed",
				"event", "ble_reconcile_stop_failed",
				"err", err,
			)
			return
		}
		n.logger.Infow(
			"ble_reconcile_stopped",
			"event", "ble_reconcile_stopped",
			"duration_ms", time.Since(started).Milliseconds(),
		)
	}
}

func (n *Subsystem) bluetoothDesired() bool {
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
		if n.bleBackoff > bleBackoffMax {
			n.bleBackoff = bleBackoffMax
		}
	}
	n.bleNextAttempt = time.Now().Add(n.bleBackoff)
}

func (n *Subsystem) bleBackoffReset() {
	n.bleBackoff = 0
	n.bleNextAttempt = time.Time{}
}

// pushBluetoothCharacteristics writes fresh state into BLE characteristics.
func (n *Subsystem) pushBluetoothCharacteristics() {
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
