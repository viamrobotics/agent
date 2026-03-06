package agent

import (
	_ "embed"
)

const (
	serviceName = "viam-agent"
)

//go:embed viam-agent.service
var serviceFileContents []byte
