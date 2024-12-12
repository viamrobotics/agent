package agent

import (
	"context"
	"regexp"
	"syscall"
	"time"

	errw "github.com/pkg/errors"
)

// HealthCheck sends a USR1 signal to the subsystem process, which should cause it to log "HEALTHY" to stdout.
func (is *InternalSubsystem) HealthCheck(ctx context.Context) (errRet error) {
	is.startStopMu.Lock()
	defer is.startStopMu.Unlock()
	is.mu.Lock()
	defer is.mu.Unlock()
	if !is.running {
		return errw.Errorf("%s not running", is.name)
	}

	is.logger.Debugf("starting healthcheck for %s", is.name)

	checkChan, err := is.cmd.Stdout.(*MatchingLogger).AddMatcher("healthcheck", regexp.MustCompile(`HEALTHY`), true)
	if err != nil {
		return err
	}
	defer func() {
		matcher, ok := is.cmd.Stdout.(*MatchingLogger)
		if ok {
			matcher.DeleteMatcher("healthcheck")
		}
	}()

	err = is.cmd.Process.Signal(syscall.SIGUSR1)
	if err != nil {
		is.logger.Error(err)
	}

	select {
	case <-time.After(time.Second * 30):
	case <-ctx.Done():
	case <-checkChan:
		is.logger.Debugf("healthcheck for %s is good", is.name)
		return nil
	}
	return errw.Errorf("timeout waiting for healthcheck on %s", is.name)
}
