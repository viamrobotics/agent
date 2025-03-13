package main

import (
	"context"
	"fmt"
	"os"

	"github.com/viamrobotics/agent"
	"github.com/viamrobotics/agent/utils"
	"go.viam.com/rdk/logging"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
)

var elog debug.Log
var _ svc.Handler = (*agentService)(nil)

const serviceName = "viam-agent"

type agentService struct{}

// Execute is the control loop for a windows service.
// This implements svc.Handler and gets called by svc.Run in main().
func (*agentService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		c := <-r
		if c.Cmd == svc.Stop || c.Cmd == svc.Shutdown {
			elog.Info(1, fmt.Sprintf("%s service stopping", serviceName))
			break
		} else {
			elog.Error(1, fmt.Sprintf("unexpected control request #%d", c))
		}
	}
	changes <- svc.Status{State: svc.StopPending}
	return
}

func main() {
	if inService, err := svc.IsWindowsService(); err != nil {
		panic(err)
	} else if !inService {
		println("no service detected -- running as normal process")
		commonMain()
		return
	}

	var err error
	elog, err = eventlog.Open(serviceName)
	if err != nil {
		return
	}
	defer elog.Close()

	elog.Info(1, fmt.Sprintf("starting %s service", serviceName))
	go commonMain()
	// note: svc.Run hangs until windows terminates the service. Then we manually call
	// globalCancel, which stops the go commonMain goroutine, then we wait for the waitgroup.
	err = svc.Run(serviceName, &agentService{})
	if err != nil {
		elog.Error(1, fmt.Sprintf("%s service failed: %v", serviceName, err))
		return
	}
	if globalCancel == nil {
		elog.Error(1, "globalCancel is nil, shutdown will be unclean")
	} else {
		globalCancel()
	}
	// wait first so viam-server doesn't try to restart
	activeBackgroundWorkers.Wait()
	// KillTree to catch any stragglers
	if err := utils.KillTree(-1); err != nil {
		elog.Error(1, fmt.Sprintf("error killing subtree %s", err))
	}
	elog.Info(1, fmt.Sprintf("%s service stopped", serviceName))
}

func ignoredSignal(_ os.Signal) bool {
	return false
}

func waitOnline(logger logging.Logger, _ context.Context) {
	logger.Debug("WaitOnline not available on windows yet")
}

func runPlatformProvisioning(_ context.Context, _ utils.AgentConfig, _ *agent.Manager, _ error) bool {
	return false
}
