package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

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
			pid := os.Getegid()
			cmd := exec.Command("wmic", "process", "where", fmt.Sprintf("ParentProcessId=%d", strconv.Itoa(pid)), "get", "ProcessId")
			output, err := cmd.Output()
			if err != nil {
				elog.Error(1, fmt.Sprintf("error getting child process for #%d, #%s", pid, err))
			}
			lines := strings.Split(string(output), "\n")
			for _, line := range lines[1:] {
				if line == "" {
					continue
				}
				var childPID int
				_, err := fmt.Sscan(line, &childPID)
				if err != nil {
					elog.Error(1, fmt.Sprintf("not a valid childProcess line %s, #%s", line, err))
					continue
				}
				cmd = exec.Command("taskkill", "/F", "/T", "/PID", strconv.Itoa(childPID))
				err = cmd.Run()
				if err != nil {
					elog.Error(1, fmt.Sprintf("error running taskkill #%s", err))
				}
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
