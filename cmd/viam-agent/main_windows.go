package main

import (
	"fmt"
	"os"

	"github.com/viamrobotics/agent/utils"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
)

var elog debug.Log

const serviceName = "viam-agent"

type agentService struct{}

// control loop for a windows service
func (*agentService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		c := <-r
		if c.Cmd == svc.Stop || c.Cmd == svc.Shutdown {
			elog.Info(1, fmt.Sprintf("%s service stopping", serviceName))
			if err := utils.KillTree(-1); err != nil {
				elog.Error(1, fmt.Sprintf("error killing subtree %s", err))
			}
			elog.Info(1, "taskkilled")
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
	err = svc.Run(serviceName, &agentService{})
	if err != nil {
		elog.Error(1, fmt.Sprintf("%s service failed: %v", serviceName, err))
		return
	}
	// todo(windows): gracefully stop. without this, RDK stays running in the background.
	elog.Info(1, fmt.Sprintf("%s service stopped", serviceName))
}

func ignoredSignal(sig os.Signal) bool {
	return false
}
