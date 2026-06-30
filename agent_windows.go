package agent

import (
	"context"

	"go.viam.com/rdk/logging"
)

// Neither the service name nor the serviceFileContents are relevant on Windows. These are
// just placeholders to make sure agent.go compiles on Windows.

const (
	serviceName = "viam-agent"

	// exitProbeScriptName is unused on Windows; the exit probe is a Linux/systemd
	// ExecStopPost= helper.
	exitProbeScriptName = ""
)

// AgentETW is the Event Tracing for Windows (ETW) identity for viam-agent.
// External tooling keys off these values, so they must not change. The GUID is
// distinct from viam-server's so agent and server traces stay separable.
var AgentETW = logging.ETWProvider{
	ProviderName: "viam-agent",
	ProviderGUID: "72682EED-9757-4411-8353-922A9D01E298",
	SessionName:  "viam-agent-trace",
}

var serviceFileContents []byte

// exitProbeScriptContents is nil on Windows; the exit probe is Linux/systemd only.
var exitProbeScriptContents []byte

// InstallNewVersion is a no-op on Windows as there is no system service update mechanism.
func InstallNewVersion(_ context.Context, _ logging.Logger) (bool, error) {
	return true, nil
}
