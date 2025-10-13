package viamserver

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"testing"

	"go.viam.com/rdk/logging"
	"go.viam.com/test"
	"go.viam.com/utils"
)

func TestCheckRestartProperty(t *testing.T) {
	logger := logging.NewTestLogger(t)
	ctx := context.Background()

	expectedRestartStatusResponse := RestartStatusResponse{
		RestartAllowed:            false,
		DoesNotHandleNeedsRestart: true,
	}

	// Set up an HTTP server that reports the expected RestartStatusResponse at the address
	// http://localhost:8080/restart_status.
	mux := http.NewServeMux()
	mux.HandleFunc("/restart_status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		test.That(t, json.NewEncoder(w).Encode(expectedRestartStatusResponse), test.ShouldBeNil)
	})
	// Use NewPossiblySecureHTTPServer to mimic RDK's behavior.
	httpServer, err := utils.NewPossiblySecureHTTPServer(mux, utils.HTTPServerOptions{
		Secure: false,
		Addr:   "localhost:8080",
	})
	test.That(t, err, test.ShouldBeNil)
	ln, err := net.Listen("tcp", "localhost:8080")
	test.That(t, err, test.ShouldBeNil)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := httpServer.Serve(ln)
		if err != nil {
			println(err.Error())
		}
	}()
	t.Cleanup(func() {
		test.That(t, httpServer.Shutdown(ctx), test.ShouldBeNil)
		wg.Wait()
	})

	// Create a new viamserver object with mostly empty fields except for checkURL and
	// checkURLAlt.
	s := &viamServer{
		logger:      logger,
		checkURL:    "http://localhost:8080",
		checkURLAlt: "http://127.0.0.1:8080",
	}

	// Run checkRestartProperty on the viamserver object and ensure that expected values are
	// returned with no errors.
	s.mu.Lock()
	restartAllowed, err := s.checkRestartProperty(ctx, RestartPropertyRestartAllowed)
	s.mu.Unlock()
	test.That(t, err, test.ShouldBeNil)
	test.That(t, restartAllowed, test.ShouldEqual, expectedRestartStatusResponse.RestartAllowed)

	s.mu.Lock()
	doesNotHandle, err := s.checkRestartProperty(ctx, RestartPropertyDoesNotHandleNeedsRestart)
	s.mu.Unlock()
	test.That(t, err, test.ShouldBeNil)
	test.That(t, doesNotHandle, test.ShouldEqual, expectedRestartStatusResponse.DoesNotHandleNeedsRestart)
}
