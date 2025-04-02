package main

import "go.viam.com/rdk/logging"

func main() {
	if !parseOpts() {
		return
	}

	// using the logger because it handily unwraps errors for us
	logger := logging.NewDebugLogger("provisioning-client")

	if opts.BTScan || opts.BTMode {
		if err := btClient(); err != nil {
			logger.Error(err)
		}
	} else {
		if err := grpcClient(); err != nil {
			logger.Error(err)
		}
	}
}
