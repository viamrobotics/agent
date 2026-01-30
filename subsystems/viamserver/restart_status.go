package viamserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"testing"
	"time"

	errw "github.com/pkg/errors"
	"github.com/samber/mo"
	goutils "go.viam.com/utils"
)

// RestartStatusResponse is the http/json response from viamserver's /restart_status URL.
type RestartStatusResponse struct {
	// RestartAllowed represents whether this instance of the viamserver can be
	// safely restarted.
	RestartAllowed bool `json:"restart_allowed"`
	// DoesNotHandleNeedsRestart represents whether this instance of the viamserver does
	// not check for the need to restart against app itself and, thus, needs agent to do so.
	// Newer versions of viamserver (>= v0.9x.0) will report true for this value, while
	// older versions won't report it at all, and agent should let viamserver handle
	// NeedsRestart logic.
	DoesNotHandleNeedsRestart bool `json:"does_not_handle_needs_restart,omitempty"`
	// ModuleServerTCPAddr is the TCP address of the module server.
	// The module server can be used for unauthenticated local RPC calls.
	// Newer versions of viamserver (>= v0.112.0) will return the address, while
	// older versions won't, and therefore won't dump stack traces on app triggered restarts.
	ModuleServerTCPAddr string `json:"module_server_tcp_addr,omitempty"`
}

const (
	restartURLSuffix = "/restart_status"

	fetchRestartStatusTimeout = 10 * time.Second
)

// Creates test URLs for restart status checks. Must be called with s.mu locked.
func (s *viamServer) makeTestURLs() ([]string, error) {
	urls := []string{s.checkURL, s.checkURLAlt}
	// On Windows, the local IPV4 addresses created below this check will not be reachable.
	// Tests for fetchRestartStatus are also unable to reach the local IPV4s created below
	// due to how the test server is set up.
	if runtime.GOOS == "windows" || testing.Testing() {
		return urls, nil
	}

	port := "8080"
	mainURL, err := url.Parse(s.checkURL)
	if err != nil {
		s.logger.Warn("Cannot determine port for restart status check, using default of 8080")
	} else {
		port = mainURL.Port()
	}

	ips, err := getAllLocalIPv4s()
	if err != nil {
		return []string{}, err
	}
	for _, ip := range ips {
		urls = append(urls, fmt.Sprintf("https://%s:%s", ip, port))
	}

	return urls, nil
}

// Gets all local IPV4s. Copied from goutils, but loopback checks are removed, as we DO
// want loopback adapters. Used in creating test URLS.
func getAllLocalIPv4s() ([]string, error) {
	allInterfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	all := []string{}

	for _, i := range allInterfaces {
		addrs, err := i.Addrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				_, bits := v.Mask.Size()
				if bits != 32 {
					// this is what limits to ipv4
					continue
				}

				all = append(all, v.IP.String())
			default:
				return nil, fmt.Errorf("unknown address type: %T", v)
			}
		}
	}

	return all, nil
}

// fetchRestartStatus fetches the full RestartStatusResponse from viam-server.
// Must be called with s.mu held, as makeTestURLs is called.
func (s *viamServer) fetchRestartStatus(ctx context.Context) (*RestartStatusResponse, error) {
	urls, err := s.makeTestURLs()
	if err != nil {
		return nil, err
	}

	// Create a buffered channel for Result[*RestartStatusResponse] values. Sending to this channel should not
	// block, as we'll only ever have len(urls) goroutines trying to send one value.
	resultChan := make(chan mo.Result[*RestartStatusResponse], len(urls))

	timeoutCtx, cancelFunc := context.WithTimeout(ctx, fetchRestartStatusTimeout)
	defer cancelFunc()

	// Disabling the cert verification because it doesn't work in offline mode (when
	// connecting to localhost).
	//nolint:gosec
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	defer func() {
		// CloseIdleConnections at the end of the method to ensure that any goroutine created
		// below does not leave an idle HTTP connection open to the server.
		client.CloseIdleConnections()
	}()

	for _, url := range urls {
		go func() {
			restartURL := url + restartURLSuffix

			req, err := http.NewRequestWithContext(timeoutCtx, http.MethodGet, restartURL, nil)
			if err != nil {
				resultChan <- mo.Err[*RestartStatusResponse](
					errw.Wrapf(err, "creating HTTP request for restart status via %s", restartURL))
				return
			}

			resp, err := client.Do(req)
			if err != nil {
				resultChan <- mo.Err[*RestartStatusResponse](
					errw.Wrapf(err, "sending HTTP request for restart status via %s", restartURL))
				return
			}
			defer func() {
				goutils.UncheckedError(resp.Body.Close())
			}()

			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				// Interacting with older viam-server instances will result in a non-successful
				// HTTP response status code, as the /restart_status endpoint will not be
				// available.
				resultChan <- mo.Errf[*RestartStatusResponse]("checking restart status via %s, got code: %d", restartURL, resp.StatusCode)
				return
			}

			var restartStatusResponse RestartStatusResponse
			if err = json.NewDecoder(resp.Body).Decode(&restartStatusResponse); err != nil {
				resultChan <- mo.Err[*RestartStatusResponse](
					errw.Wrapf(err, "decoding HTTP response for restart status via %s", restartURL))
				return
			}

			resultChan <- mo.Ok(&restartStatusResponse)
		}()
	}

	var combinedErr error
	for range urls {
		select {
		case result := <-resultChan:
			response, err := result.Get()
			if err != nil {
				combinedErr = errors.Join(combinedErr, err)
			} else {
				// We assume below that the first test URL through which we encountered the feature's
				// value represents the actual value.
				return response, nil
			}
		case <-timeoutCtx.Done():
			return nil, errors.Join(combinedErr, ctx.Err())
		}
	}
	return nil, combinedErr
}
