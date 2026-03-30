package main

import (
	"os/exec"
	"sync"
	"testing"

	"go.viam.com/test"
)

func Test(t *testing.T) {
	startedWg := &sync.WaitGroup{}
	startedWg.Add(3)
	doneWg := &sync.WaitGroup{}
	for range 3 {
		cmd := exec.CommandContext(t.Context(), "powershell.exe", "-Command", "Start-Sleep -Seconds 10")
		doneWg.Go(func() {
			err := cmd.Start()
			startedWg.Done()
			test.That(t, err, test.ShouldBeNil)
			cmd.Wait()
		})
	}
	startedWg.Wait()
	killed, err := zapChildren(t.Context())
	test.That(t, err, test.ShouldBeNil)
	test.That(t, killed, test.ShouldEqual, 3)
	doneWg.Wait()
}
