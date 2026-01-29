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

type (
	// RestartStatusResponse is the http/json response from viamserver's /restart_status URL.
	RestartStatusResponse struct {
		// RestartAllowed represents whether this instance of the viamserver can be
		// safely restarted.
		RestartAllowed bool `json:"restart_allowed"`
		// DoesNotHandleNeedsRestart represents whether this instance of the viamserver does
		// not check for the need to restart against app itself and, thus, needs agent to do so.
		// Newer versions of viamserver (>= v0.9x.0) will report true for this value, while
		// older versions won't report it at all, and agent should let viamserver handle
		// NeedsRestart logic.
		DoesNotHandleNeedsRestart bool `json:"does_not_handle_needs_restart,omitempty"`
		// ModuleServerTCPAddr is the TCP address of the module server, if available.
		// The module server can be used for unauthenticated local RPC calls.
		ModuleServerTCPAddr string `json:"module_server_tcp_addr,omitempty"`
	}

	// restartProperty is a property related to restarting about which agent can query
	// viamserver.
	restartProperty = string
)

const (
	RestartPropertyRestartAllowed            restartProperty = "restart allowed"
	RestartPropertyDoesNotHandleNeedsRestart restartProperty = "does not handle needs restart"

	restartURLSuffix = "/restart_status"

	checkRestartPropertyTimeout = 10 * time.Second
)

// Creates test URLs for property checks. Must be called with s.mu locked.
func (s *viamServer) makeTestURLs(rp restartProperty) ([]string, error) {
	urls := []string{s.checkURL, s.checkURLAlt}
	// On Windows, the local IPV4 addresses created below this check will not be reachable.
	// Tests for checkRestartProperty are also unable to reach the local IPV4s created below
	// due to how the test server is set up.
	if runtime.GOOS == "windows" || testing.Testing() {
		return urls, nil
	}

	port := "8080"
	mainURL, err := url.Parse(s.checkURL)
	if err != nil {
		s.logger.Warnf("Cannot determine port for %s check, using default of 8080", rp)
	} else {
		port = mainURL.Port()
		s.logger.Debugf("Using port %s for %s check", port, rp)
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

// Returns the value of the requested restart property (false if not determined) and any
// encountered errors. Must be called with s.mu held, as makeTestURLs is called.
func (s *viamServer) checkRestartProperty(ctx context.Context, rp restartProperty) (bool, error) {
	resp, err := s.fetchRestartStatus(ctx)
	if err != nil {
		return false, err
	}

	switch rp {
	case RestartPropertyRestartAllowed:
		return resp.RestartAllowed, nil
	case RestartPropertyDoesNotHandleNeedsRestart:
		return resp.DoesNotHandleNeedsRestart, nil
	default:
		return false, errw.Errorf("unknown restart property: %s", rp)
	}
}

// fetchRestartStatus fetches the full RestartStatusResponse from viam-server.
// Must be called with s.mu held, as makeTestURLs is called.
func (s *viamServer) fetchRestartStatus(ctx context.Context) (*RestartStatusResponse, error) {
	urls, err := s.makeTestURLs("restart status")
	if err != nil {
		return nil, err
	}

	resultChan := make(chan mo.Result[*RestartStatusResponse], len(urls))

	timeoutCtx, cancelFunc := context.WithTimeout(ctx, checkRestartPropertyTimeout)
	defer cancelFunc()

	//nolint:gosec
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	defer func() {
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
				resultChan <- mo.Errf[*RestartStatusResponse](
					"checking restart status via %s, got code: %d", restartURL, resp.StatusCode)
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
				return response, nil
			}
		case <-timeoutCtx.Done():
			return nil, errors.Join(combinedErr, ctx.Err())
		}
	}
	return nil, combinedErr
}
