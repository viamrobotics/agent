//go:build linux

package networking

import (
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
