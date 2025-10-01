package systemd

import (
	"os/exec"
	"strings"

	"github.com/pkg/errors"
)

// SystemdExecutor executes various systemd commands as subprocess. It
// primarily exists to enable testing of higher level systemd manipulation via
// mocks or fakes.
type SystemdExecutor interface {
	// IsAvailable checks if systemd is available on the system. Currently it does
	// this by executing `systemctl --version` and checking the output. It returns
	// nil if systemd is available and an error describing why it is unavailable
	// otherwise.
	IsAvailable() error

	// DaemonReload executes `systemctl daemon-reload`.
	DaemonReload() error

	// Enable calls `systemctl enable` with the provided service name.
	Enable(service string) error

	// SystemPath gets the unit search paths by calling `systemd-path
	// systemd-search-system-unit`. It automatically splits the result around
	// `:`.
	SystemdSearchPaths() ([]string, error)
}

type realSystemdExecutor struct{}

func (s realSystemdExecutor) IsAvailable() error {
	cmd := exec.Command("systemctl", "--version")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "systemctl --version returned errors: %s", output)
	}
	return nil
}

func (s realSystemdExecutor) Enable(service string) error {
	cmd := exec.Command("systemctl", "enable", "viam-agent")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "running 'systemctl enable %s' output: %s", service, output)
	}
	return nil
}

func (s realSystemdExecutor) DaemonReload() error {
	cmd := exec.Command("systemctl", "daemon-reload")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return errors.Wrapf(err, "running 'systemctl daemon-reload' output: %s", output)
	}
	return nil
}

func (s realSystemdExecutor) SystemdSearchPaths() ([]string, error) {
	cmd := exec.Command("systemd-path", "systemd-search-system-unit")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, errors.Wrapf(err, "running 'systemd-path systemd-search-system-unit' output: %s", output)
	}
	return strings.Split(strings.TrimSpace(string(output)), ":"), nil
}
