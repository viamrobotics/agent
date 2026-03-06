package agent

import (
	_ "embed"
)

const (
	serviceName = "com.viam.agent"
)

//go:embed com.viam.agent.plist
var serviceFileContents []byte
