package main

import (
	"context"
	"flag"

	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
)

var url = flag.String("url", "", "URL to use for testing")
var dest = flag.String("dest", "", "output path")

func main() {
	// todo: test strategy for resumable and non resumable URLs
	flag.Parse()
	logger := logging.NewDebugLogger("partial-dl")
	if err := utils.DownloadWithPartial(context.Background(), *url, *dest, logger); err != nil {
		panic(err)
	}
}
