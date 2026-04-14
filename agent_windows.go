package agent

import (
	"context"

	"go.viam.com/rdk/logging"
)

// Neither the service name nor the serviceFileContents are relevant on Windows. These are
// just placeholders to make sure agent.go compiles on Windows.

const (
	serviceName = "viam-agent"
)

var serviceFileContents []byte

// InstallNewVersion is a no-op on Windows as there is no system service update mechanism.
func InstallNewVersion(_ context.Context, _ logging.Logger) (bool, error) {
	return true, nil
}
