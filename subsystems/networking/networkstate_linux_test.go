//go:build linux

package networking

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"

	"go.viam.com/rdk/logging"
)

func TestNetworkStateLockOrder(t *testing.T) {
	ns := NewNetworkState(logging.NewTestLogger(t))
	id := ns.GenNetKey(NetworkTypeWifi, "wlan0", "test")
	ns.SetNetwork(id, network{ssid: "test", interfaceName: "wlan0"})

	const iters = 2000
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			_ = ns.Network(id)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iters; i++ {
			ln := ns.LockingNetwork(id)
			ln.mu.Lock()
			ns.SetActiveConn("wlan0", nil)
			ln.mu.Unlock()
		}
	}()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		t.Fatalf("deadlock — test hung:\n%s", buf[:n])
	}
}

// Broad concurrency stress: exercises networkState's public surface so -race
// surfaces unsynchronized field access.
func TestNetworkStateConcurrentAccess(t *testing.T) {
	ns := NewNetworkState(logging.NewTestLogger(t))

	ifaces := []string{"wlan0", "wlan1", "eth0"}
	ssids := []string{"a", "b", "c"}
	for _, iface := range ifaces {
		for _, ssid := range ssids {
			id := ns.GenNetKey(NetworkTypeWifi, iface, ssid)
			ns.SetNetwork(id, network{ssid: ssid, interfaceName: iface})
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	run := func(fn func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				fn()
			}
		}()
	}

	run(func() { _ = ns.Networks() })
	run(func() { _ = ns.LockingNetworks() })
	run(func() { _ = ns.Devices() })

	run(func() {
		for _, iface := range ifaces {
			for _, ssid := range ssids {
				_ = ns.Network(ns.GenNetKey(NetworkTypeWifi, iface, ssid))
			}
		}
	})

	run(func() {
		id := ns.GenNetKey(NetworkTypeWifi, ifaces[0], ssids[0])
		ln := ns.LockingNetwork(id)
		ln.mu.Lock()
		ln.connected = !ln.connected
		ln.lastError = errors.New("test")
		ln.signal++
		ln.mu.Unlock()
	})

	run(func() {
		for _, iface := range ifaces {
			ns.SetActiveSSID(iface, "x")
			ns.SetLastSSID(iface, "y")
			ns.SetPrimarySSID(iface, "z")
			ns.SetActiveConn(iface, nil)
		}
	})

	wg.Wait()
}
