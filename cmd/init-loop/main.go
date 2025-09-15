// this loops the networking subsystem's init function to try to repro bluetooth issues.
package main

import (
	"context"
	"flag"

	"github.com/viamrobotics/agent/subsystems/networking"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
)

var count = flag.Int("count", 2, "how many iterations")

func main() {
	flag.Parse()
	ctx := context.Background()
	cfg := utils.AgentConfig{}
	logger := logging.NewDebugLogger("initloop")
	nw := networking.NewSubsystem(ctx, logger, cfg).(*networking.Networking)
	for range *count {
		if err := nw.Init(ctx); err != nil {
			panic(err)
		}
	}
}
