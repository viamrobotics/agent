package launchd

import (
	"context"
	"os/exec"

	"github.com/pkg/errors"
)

// Commands are expected to run on the "system" domain.
const systemDomain = "system"

// LaunchdExecutor executes various launchd commands as subprocesses. It primarily exists
// to enable testing of higher level launchd manipulation via mocks or fakes.
type LaunchdExecutor interface {
	// IsAvailable checks if launchd is available on the system. Currently it does this by
	// executing `launchctl version` and checking the output. It returns nil if launchd is
	// available and an error describing why it is unavailable otherwise.
	IsAvailable(ctx context.Context) error

	// Bootstrap executes `launchctl bootstrap` with the "system" domain and path to a
	// .plist file.
	Bootstrap(ctx context.Context, serviceFilePath string) error

	// Bootout executes `launchctl bootout` with the "system" domain and the provided
	// service name.
	Bootout(ctx context.Context, service string) error

	// Enable executes `launchctl enable` with the "system" domain and the provided service
	// name.
	Enable(ctx context.Context, service string) error
}

type realLaunchdExecutor struct{}

func (s realLaunchdExecutor) IsAvailable(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "launchctl", "version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "'launchctl version' returned errors: %s", output)
	}
	return nil
}

func (s realLaunchdExecutor) Bootstrap(ctx context.Context, serviceFilePath string) error {
	cmd := exec.CommandContext(ctx, "launchctl", "bootstrap", systemDomain, serviceFilePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "running 'launchctl bootstrap %s %s' output: %s", systemDomain, serviceFilePath, output)
	}
	return nil
}

func (s realLaunchdExecutor) Bootout(ctx context.Context, service string) error {
	cmd := exec.CommandContext(ctx, "launchctl", "bootout", systemDomain+"/"+service)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "running 'launchctl bootout %s %s' output: %s", systemDomain, service, output)
	}
	return nil
}

func (s realLaunchdExecutor) Enable(ctx context.Context, service string) error {
	cmd := exec.CommandContext(ctx, "launchctl", "enable", systemDomain+"/"+service)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "running 'launchctl enable %s/%s' output: %s", systemDomain, service, output)
	}
	return nil
}
