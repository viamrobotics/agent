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
	"time"

	errw "github.com/pkg/errors"
	goutils "go.viam.com/utils"
)

type (
	// RestartPropertyGetter is a limited interface through which agent can access
	// information about viamserver related to restarting.
	RestartPropertyGetter interface {
		// RestartAllowed checks whether viamserver is safe to restart.
		RestartAllowed(ctx context.Context) bool
		// DoesNotHandlesNeedsRestart checks whether viamserver does not itself check for the
		// need to restart against app.
		DoesNotHandleNeedsRestart(ctx context.Context) bool
	}

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
	}

	// restartProperty is a property related to restarting about which agent can query
	// viamserver.
	restartProperty string
)

const (
	restartPropertyRestartAllowed            restartProperty = "restart allowed"
	restartPropertyDoesNotHandleNeedsRestart                 = "does not handle need restart"

	restartURLSuffix = "/restart_status"

	checkRestartPropertyTimeout = 10 * time.Second
)

// Creates test URLs for property checks. Must be called with s.mu locked.
func (s *viamServer) makeTestURLs() ([]string, error) {
	port := "8080"
	mainURL, err := url.Parse(s.checkURL)
	if err != nil {
		s.logger.Warnf("cannot determine port for restart allowed check, using default of 8080")
	} else {
		port = mainURL.Port()
		s.logger.Debugf("using port %s for restart allowed check", port)
	}

	ips, err := getAllLocalIPv4s()
	if err != nil {
		return []string{}, err
	}

	urls := []string{s.checkURL, s.checkURLAlt}
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
	urls, err := s.makeTestURLs()
	if err != nil {
		return false, err
	}

	errorChan := make(chan error, len(urls))
	propertyValueChan := make(chan bool, len(urls))
	timeoutCtx, cancelFunc := context.WithTimeout(ctx, checkRestartPropertyTimeout)
	defer cancelFunc()

	for _, url := range urls {
		go func() {
			s.logger.Debugf("Starting %s check for %s using %s", rp, SubsysName, url)

			restartURL := url + restartURLSuffix

			req, err := http.NewRequestWithContext(timeoutCtx, http.MethodGet, restartURL, nil)
			if err != nil {
				errorChan <- errw.Wrapf(err, "creating HTTP request for %s check for %s via %s",
					rp, SubsysName, restartURL)
				return
			}

			// Disabling the cert verification because it doesn't work in offline mode (when
			// connecting to localhost).
			//nolint:gosec
			client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

			resp, err := client.Do(req)
			if err != nil {
				errorChan <- errw.Wrapf(err, "sending HTTP request for %s check for %s via %s",
					rp, SubsysName, restartURL)
				return
			}
			defer func() {
				goutils.UncheckedError(resp.Body.Close())
			}()

			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				// Interacting with older viam-server instances will result in a non-successful
				// HTTP response status code, as the /restart_status endpoint will not be
				// available. Report false (default) as the feature value and continue to next
				// test URL in this case.
				propertyValueChan <- false
				return
			}

			var restartStatusResponse RestartStatusResponse
			if err = json.NewDecoder(resp.Body).Decode(&restartStatusResponse); err != nil {
				errorChan <- errw.Wrapf(err, "decoding HTTP response for %s check for %s via %s",
					rp, SubsysName, restartURL)
				return
			}

			switch rp {
			case restartPropertyRestartAllowed:
				propertyValueChan <- restartStatusResponse.RestartAllowed
			case restartPropertyDoesNotHandleNeedsRestart:
				propertyValueChan <- restartStatusResponse.DoesNotHandleNeedsRestart
			}

			errorChan <- nil
		}()
	}

	var combinedErr error
	for err := range errorChan {
		combinedErr = errors.Join(combinedErr, err)
	}

	// We assume below that the first test URL through which we encountered the feature's
	// value represents the actual value.
	return <-propertyValueChan, combinedErr
}

// RestartAllowed checks whether viamserver is safe to restart.
func (s *viamServer) RestartAllowed(ctx context.Context) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running || runtime.GOOS == "windows" {
		// Assume viamserver is "safe to restart" if not running at all or on Windows.
		return true
	}

	restartAllowed, err := s.checkRestartProperty(ctx, restartPropertyRestartAllowed)
	if err != nil {
		// Log any errors encountered while checking whether restart was allowed. Do not log
		// whether viamserver has or has not reported allowance of a restart in this case, as
		// we don't know, and will just assume it's unsafe to restart.
		s.logger.Warn(err)
		return restartAllowed
	}
	if restartAllowed {
		s.logger.Infof("Will restart %s to run new version, as it has reported allowance of a restart", SubsysName)
	} else {
		s.logger.Infof("Will not restart %s version to run new version, as it has not reported allowance of a restart", SubsysName)
	}
	return restartAllowed
}

// DoesNotHandlesNeedsRestart checks whether viamserver does not itself check for the need
// to restart against app.
func (s *viamServer) DoesNotHandleNeedsRestart(ctx context.Context) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		// Assume agent can handle the restart if viamserver isn't running.
		return true
	}

	doesNotHandleNeedsRestart, err := s.checkRestartProperty(ctx,
		restartPropertyDoesNotHandleNeedsRestart)
	if err != nil {
		// Log any errors encountered while checking whether needs restart is handled.
		s.logger.Warn(err)
	}
	return doesNotHandleNeedsRestart
}
