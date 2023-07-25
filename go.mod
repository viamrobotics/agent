module github.com/viamrobotics/agent

go 1.20

require (
	github.com/edaniels/golog v0.0.0-20230215213219-28954395e8d0
	github.com/jessevdk/go-flags v1.5.0
	go.uber.org/zap v1.24.0
)

require (
	github.com/benbjohnson/clock v1.3.3 // indirect
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.8.4 // indirect
	github.com/ulikunitz/xz v0.5.11
	go.uber.org/atomic v1.10.0 // indirect
	go.uber.org/goleak v1.2.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/sys v0.8.0 // indirect
)

replace go.viam.com/rdk => ../rdk
