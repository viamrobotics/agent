package viamserver

import (
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"testing"

	"go.viam.com/rdk/logging"
	"go.viam.com/test"
	"go.viam.com/utils"
)

// Mimics an old server's response to the restart_status HTTP endpoint.
type oldRestartStatusResponse struct {
	RestartAllowed bool `json:"restart_allowed"`
}

// Ensures that fetchRestartStatus works correctly for restart_allowed and
// does_not_handle_needs_restart against a fake viamserver instance (HTTP server).
func TestFetchRestartStatus(t *testing.T) {
	logger := logging.NewTestLogger(t)
	ctx := t.Context()

	targetAddr := "localhost:8080"
	s := &viamServer{
		logger: logger,
		// checkURL will normally be the .cloud address of the machine; use localhost instead
		// here.
		checkURL: "http://" + targetAddr,
		// checkURLAlt is always 127.0.0.1:[bind-port] in agent code.
		checkURLAlt: "http://127.0.0.1:8080",
	}

	falseVal := false
	trueVal := true
	testCases := []struct {
		name                   string
		expectedRestartAllowed bool
		// Can be unset (mimic old server), false, and true.
		expectedDoesNotHandleNeedsRestart *bool
	}{
		{
			"restart_allowed=false;does_not_handle_needs_restart=unset",
			false,
			nil,
		},
		{
			"restart_allowed=false;does_not_handle_needs_restart=false",
			false,
			&falseVal,
		},
		{
			"restart_allowed=false;does_not_handle_needs_restart=true",
			false,
			&trueVal,
		},
		{
			"restart_allowed=true;does_not_handle_needs_restart=unset",
			true,
			nil,
		},
		{
			"restart_allowed=true;does_not_handle_needs_restart=false",
			true,
			nil,
		},
		{
			"restart_allowed=true;does_not_handle_needs_restart=true",
			true,
			&trueVal,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var expectedRestartStatusResponse any
			if tc.expectedDoesNotHandleNeedsRestart != nil {
				expectedRestartStatusResponse = RestartStatusResponse{
					RestartAllowed:            tc.expectedRestartAllowed,
					DoesNotHandleNeedsRestart: *tc.expectedDoesNotHandleNeedsRestart,
				}
			} else {
				expectedRestartStatusResponse = oldRestartStatusResponse{
					RestartAllowed: tc.expectedRestartAllowed,
				}
			}

			mux := http.NewServeMux()
			mux.HandleFunc("/restart_status", func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				test.That(t, json.NewEncoder(w).Encode(expectedRestartStatusResponse), test.ShouldBeNil)
			})
			// Use NewPossiblySecureHTTPServer to mimic RDK's behavior.
			httpServer, err := utils.NewPossiblySecureHTTPServer(mux, utils.HTTPServerOptions{
				Secure: false,
				Addr:   targetAddr,
			})
			test.That(t, err, test.ShouldBeNil)
			listenCfg := &net.ListenConfig{}
			ln, err := listenCfg.Listen(ctx, "tcp", targetAddr)
			test.That(t, err, test.ShouldBeNil)
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := httpServer.Serve(ln)
				// Should be "server closed" due to Shutdown below.
				test.That(t, err, test.ShouldBeError, http.ErrServerClosed)
			}()
			t.Cleanup(func() {
				test.That(t, httpServer.Shutdown(ctx), test.ShouldBeNil)
				wg.Wait()
			})

			s.mu.Lock()
			t.Cleanup(s.mu.Unlock)

			restartStatus, err := s.fetchRestartStatus(ctx)
			test.That(t, err, test.ShouldBeNil)
			test.That(t, restartStatus.RestartAllowed, test.ShouldEqual, tc.expectedRestartAllowed)

			// does_not_handle_restart should be false if explicitly false or unset in the test
			// case.
			var expectedDoesNotHandleNeedsRestart bool
			if tc.expectedDoesNotHandleNeedsRestart != nil {
				expectedDoesNotHandleNeedsRestart = *tc.expectedDoesNotHandleNeedsRestart
			}
			test.That(t, restartStatus.DoesNotHandleNeedsRestart, test.ShouldEqual, expectedDoesNotHandleNeedsRestart)
		})
	}
}
