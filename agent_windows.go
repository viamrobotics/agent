package agent

// Neither the service name nor the serviceFileContents are relevant on Windows. These are
// just placeholders to make sure agent.go compiles on Windows.

const (
	serviceName = "viam-agent"
)

var serviceFileContents []byte
